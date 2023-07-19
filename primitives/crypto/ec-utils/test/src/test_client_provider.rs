use std::process::Command;
use test_client_configurator::compose_test_client;

pub fn get_test_client(
	stack_size: i32,
) -> Result<Client<Backend, EccExecutor, Block, RuntimeApi>, ApiError> {
	let _ = Command::new("cargo")
		.env("STACK_SIZE", stack_size)
		.arg("build")
		.output()
		.expect("Failed to run build command");
	return compose_test_client(stack_size)
}
