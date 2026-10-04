use crate::msg_handler::IncomingMessage;
use crate::{error::*, sync_helpers::*};
use smb_transport::{IoVec, SmbTransport, SmbTransportRead, SmbTransportWrite, TransportError};
use std::sync::Arc;
use std::time::Duration;
use tokio::{select, sync::oneshot};

use super::backend_trait::MultiWorkerBackend;
use super::base::ParallelWorker;

#[derive(Debug, Default)]
pub struct AsyncBackend {
    /// The loop handles for the workers.
    loop_handles: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,

    token: CancellationToken,
}

impl AsyncBackend {
    /// Internal message loop handler.
    async fn loop_receive(
        self: Arc<Self>,
        mut rtransport: Box<dyn SmbTransportRead>,
        worker: Arc<ParallelWorker<Self>>,
    ) {
        tracing::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref.handle_next_recv(rtransport.as_mut(), &worker).await {
                Ok(_) => {}
                Err(Error::TransportError(TransportError::NotConnected | TransportError::IoError(_))) => {
                    tracing::error!("Connection was force-closed by the server.");
                    self_ref.token.cancel();
                    break;
                }
                Err(Error::ConnectionStopped) => {
                    break;
                }
                Err(e) => {
                    tracing::error!("Error in worker loop: {e}");
                }
            }
        }

        // Cleanup
        tracing::debug!("Cleaning up worker loop.");
        self_ref.token.cancel();
        if let Err(err) = worker.mark_stopped().await {
            tracing::error!("Failed to mark worker stopped: {err}");
        }
    }

    async fn loop_send(
        self: Arc<Self>,
        mut wtransport: Box<dyn SmbTransportWrite>,
        mut send_channel: mpsc::Receiver<IoVec>,
        worker: Arc<ParallelWorker<Self>>,
    ) {
        tracing::debug!("Starting worker loop.");
        let self_ref = self.as_ref();
        loop {
            match self_ref
                .handle_next_send(wtransport.as_mut(), &mut send_channel, &worker)
                .await
            {
                Ok(_) => {}
                Err(Error::TransportError(TransportError::NotConnected | TransportError::IoError(_))) => {
                    tracing::error!("Connection was force-closed by the server.");
                    self_ref.token.cancel();
                    break;
                }
                Err(Error::ConnectionStopped) => {
                    break;
                }
                Err(e) => {
                    tracing::error!("Error in worker loop: {e}",);
                }
            }
        }

        send_channel.close();
        self_ref.token.cancel();
        if let Err(err) = worker.mark_stopped().await {
            tracing::error!("Failed to mark worker stopped: {err}");
        }
    }

    /// Handles the next message in the receive loop:
    /// receives a message, transforms it, and sends it to the correct awaiting task.
    ///
    /// - If the connection is stopped using the `stop` method, this will return `Error::ConnectionStopped`.
    /// - A [`TransportError`] might be returned if the underlying transport fails.
    async fn handle_next_recv(
        &self,
        rtransport: &mut dyn SmbTransportRead,
        worker: &Arc<ParallelWorker<Self>>,
    ) -> crate::Result<()> {
        select! {
            // Receive a message from the server.
            result = async {
                let message_from_server = rtransport.receive().await;
                worker.incoming_data_callback(message_from_server).await
            } => result,
            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::ConnectionStopped)
            }
        }
    }

    /// Handles the next message in the send loop:
    /// sends a message to the server.
    async fn handle_next_send(
        &self,
        wtransport: &mut dyn SmbTransportWrite,
        send_channel: &mut mpsc::Receiver<IoVec>,
        worker: &Arc<ParallelWorker<Self>>,
    ) -> crate::Result<()> {
        select! {
            // Send a message to the server.
            result = async {
                let message_to_send = send_channel.recv().await.ok_or(Error::ConnectionStopped)?;
                worker.outgoing_data_callback(Some(message_to_send), wtransport).await
            } => result,
            // Cancel the loop.
            _ = self.token.cancelled() => {
                Err(Error::ConnectionStopped)
            }
        }
    }
}

impl MultiWorkerBackend for AsyncBackend {
    type SendMessage = IoVec;

    type AwaitingNotifier = oneshot::Sender<crate::Result<IncomingMessage>>;
    type AwaitingWaiter = oneshot::Receiver<crate::Result<IncomingMessage>>;

    async fn start(
        transport: Box<dyn SmbTransport>,
        worker: Arc<ParallelWorker<Self>>,
        send_channel_recv: mpsc::Receiver<Self::SendMessage>,
    ) -> crate::Result<Arc<Self>> {
        let backend: Arc<Self> = Default::default();
        let backend_clone = backend.clone();
        let (rtransport, wtransport) = transport.split()?;

        let recv_task = {
            let backend_clone = backend_clone.clone();
            let worker = worker.clone();
            tokio::spawn(async move { backend_clone.loop_receive(rtransport, worker).await })
        };

        let send_task =
            tokio::spawn(async move { backend_clone.loop_send(wtransport, send_channel_recv, worker).await });
        backend.loop_handles.lock().await?.replace((recv_task, send_task));

        Ok(backend)
    }

    async fn stop(&self) -> crate::Result<()> {
        tracing::debug!("Stopping worker.");
        self.token.cancel();
        let loop_handles = self.loop_handles.lock().await?.take().ok_or(Error::ConnectionStopped)?;
        loop_handles.0.await?;
        loop_handles.1.await?;
        Ok(())
    }
    fn wrap_msg_to_send(msg: IoVec) -> Self::SendMessage {
        msg
    }

    fn make_notifier_awaiter_pair() -> (Self::AwaitingNotifier, Self::AwaitingWaiter) {
        oneshot::channel()
    }

    async fn wait_on_waiter(waiter: Self::AwaitingWaiter, timeout: Duration) -> crate::Result<IncomingMessage> {
        if timeout == Duration::ZERO {
            waiter.await.map_err(|_| Error::ConnectionStopped)?
        } else {
            tokio::select! {
                msg = waiter => {
                    msg.map_err(|_| Error::ConnectionStopped)?
                },
                _ = tokio::time::sleep(timeout) => {
                    Err(Error::OperationTimeout(TimedOutTask::ReceiveNextMessage, timeout))
                }
            }
        }
    }

    fn send_notify(
        tx: Self::AwaitingNotifier,
        msg: crate::Result<IncomingMessage>,
    ) -> Result<(), crate::Result<IncomingMessage>> {
        tx.send(msg)
    }

    fn make_send_channel_pair() -> (mpsc::Sender<Self::SendMessage>, mpsc::Receiver<Self::SendMessage>) {
        mpsc::channel(100)
    }
}
