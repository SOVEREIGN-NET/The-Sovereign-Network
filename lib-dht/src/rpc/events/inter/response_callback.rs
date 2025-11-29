use crate::rpc::events::error_response_event::ErrorResponseEvent;
use crate::rpc::events::response_event::ResponseEvent;
use crate::rpc::events::stalled_event::StalledEvent;

pub trait ResponseCallback: Send {

    fn on_response(&self, event: ResponseEvent);

    fn on_error_response(&self, _event: ErrorResponseEvent) {
    }

    fn on_stalled(&self, _event: StalledEvent) {
    }
}
