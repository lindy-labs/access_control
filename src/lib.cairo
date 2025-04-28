mod access_control;

pub use access_control::{IAccessControlDispatcher, IAccessControlDispatcherTrait, access_control_component};
#[cfg(test)]
mod tests {
    mod mock_access_control;
    mod test_access_control;
}
