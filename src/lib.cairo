pub mod access_control;

use access_control::{access_control_component, IAccessControlDispatcher, IAccessControlDispatcherTrait};
#[cfg(test)]
mod tests {
    mod mock_access_control;
    mod test_access_control;
}
