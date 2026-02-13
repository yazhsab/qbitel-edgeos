"""Command-line interface for Qbitel EdgeOS provisioning tool."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .keygen import KeyGenerator, KeyType
from .flash import FlashProgrammer, FlashTarget
from .verify import ProvisioningVerifier
from .config import ProvisioningConfig, load_config
from .identity import IdentityGenerator

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="q-provision")
@click.option("--config", "-c", type=click.Path(exists=True), help="Configuration file path")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, config: Optional[str], verbose: bool) -> None:
    """Qbitel EdgeOS Factory Provisioning Tool.

    Provision quantum-resistant device identities and keys for Qbitel EdgeOS devices.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if config:
        ctx.obj["config"] = load_config(Path(config))
    else:
        ctx.obj["config"] = ProvisioningConfig()


@main.command()
@click.option(
    "--key-type",
    "-t",
    type=click.Choice(["kyber768", "dilithium3", "falcon512", "all"]),
    default="all",
    help="Type of keys to generate",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output directory for keys")
@click.option("--device-id", "-d", required=True, help="Device identifier (hex string)")
@click.option(
    "--manufacturer-id", "-m", default="0001", help="Manufacturer identifier (hex string)"
)
@click.pass_context
def keygen(
    ctx: click.Context,
    key_type: str,
    output: str,
    device_id: str,
    manufacturer_id: str,
) -> None:
    """Generate post-quantum cryptographic keys for device provisioning."""
    config: ProvisioningConfig = ctx.obj["config"]
    verbose: bool = ctx.obj["verbose"]

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold blue]Generating keys for device {device_id}[/bold blue]")

    try:
        device_id_bytes = bytes.fromhex(device_id)
        manufacturer_id_bytes = bytes.fromhex(manufacturer_id)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid hex string: {e}")
        sys.exit(1)

    generator = KeyGenerator(config.crypto)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        if key_type in ("kyber768", "all"):
            task = progress.add_task("Generating Kyber-768 KEM keypair...", total=1)
            kem_keypair = generator.generate_keypair(KeyType.KYBER768)
            kem_keypair.save(output_path / "kem")
            progress.update(task, completed=1)
            if verbose:
                console.print(f"  KEM public key: {kem_keypair.public_key[:32].hex()}...")

        if key_type in ("dilithium3", "all"):
            task = progress.add_task("Generating Dilithium-3 signature keypair...", total=1)
            sig_keypair = generator.generate_keypair(KeyType.DILITHIUM3)
            sig_keypair.save(output_path / "sig")
            progress.update(task, completed=1)
            if verbose:
                console.print(f"  Signature public key: {sig_keypair.public_key[:32].hex()}...")

        if key_type in ("falcon512", "all"):
            task = progress.add_task("Generating Falcon-512 signature keypair...", total=1)
            falcon_keypair = generator.generate_keypair(KeyType.FALCON512)
            falcon_keypair.save(output_path / "falcon")
            progress.update(task, completed=1)
            if verbose:
                console.print(f"  Falcon public key: {falcon_keypair.public_key[:32].hex()}...")

    # Save device metadata
    metadata = {
        "device_id": device_id,
        "manufacturer_id": manufacturer_id,
        "key_types": [key_type] if key_type != "all" else ["kyber768", "dilithium3", "falcon512"],
    }
    import json

    with open(output_path / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    console.print(f"[bold green]✓[/bold green] Keys saved to {output_path}")


@main.command()
@click.option("--device-id", "-d", required=True, help="Device identifier (hex string)")
@click.option(
    "--manufacturer-id", "-m", default="0001", help="Manufacturer identifier (hex string)"
)
@click.option(
    "--device-class",
    type=click.Choice(["gateway", "sensor", "actuator", "controller"]),
    default="gateway",
    help="Device class",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output directory")
@click.option("--puf-data", type=click.Path(exists=True), help="PUF challenge-response data file")
@click.pass_context
def identity(
    ctx: click.Context,
    device_id: str,
    manufacturer_id: str,
    device_class: str,
    output: str,
    puf_data: Optional[str],
) -> None:
    """Generate device identity commitment and hardware binding."""
    config: ProvisioningConfig = ctx.obj["config"]
    verbose: bool = ctx.obj["verbose"]

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold blue]Creating identity for device {device_id}[/bold blue]")

    try:
        device_id_bytes = bytes.fromhex(device_id)
        manufacturer_id_bytes = bytes.fromhex(manufacturer_id)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid hex string: {e}")
        sys.exit(1)

    # Load PUF data if provided
    puf_response = None
    if puf_data:
        with open(puf_data, "rb") as f:
            puf_response = f.read()

    generator = IdentityGenerator(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating cryptographic keys...", total=1)
        identity = generator.generate_identity(
            device_id=device_id_bytes,
            manufacturer_id=manufacturer_id_bytes,
            device_class=device_class,
            puf_response=puf_response,
        )
        progress.update(task, completed=1)

        task = progress.add_task("Creating identity commitment...", total=1)
        commitment = generator.create_commitment(identity)
        progress.update(task, completed=1)

        task = progress.add_task("Saving identity data...", total=1)
        generator.save_identity(identity, commitment, output_path)
        progress.update(task, completed=1)

    console.print(f"[bold green]✓[/bold green] Identity created at {output_path}")

    if verbose:
        table = Table(title="Identity Summary")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Device ID", device_id)
        table.add_row("Manufacturer ID", manufacturer_id)
        table.add_row("Device Class", device_class)
        table.add_row("Commitment Hash", commitment.hash[:32].hex() + "...")
        console.print(table)


@main.command()
@click.option("--port", "-p", required=True, help="Serial port or debug probe")
@click.option(
    "--target",
    "-t",
    type=click.Choice(["stm32h7", "stm32u5", "riscv"]),
    required=True,
    help="Target platform",
)
@click.option("--identity", "-i", type=click.Path(exists=True), required=True, help="Identity data directory")
@click.option("--bootloader", type=click.Path(exists=True), help="Bootloader binary")
@click.option("--kernel", type=click.Path(exists=True), help="Kernel binary")
@click.option("--verify", is_flag=True, default=True, help="Verify after flashing")
@click.option("--lock", is_flag=True, help="Lock flash after programming (production only)")
@click.pass_context
def flash(
    ctx: click.Context,
    port: str,
    target: str,
    identity: str,
    bootloader: Optional[str],
    kernel: Optional[str],
    verify: bool,
    lock: bool,
) -> None:
    """Flash device identity and firmware to target device."""
    config: ProvisioningConfig = ctx.obj["config"]
    verbose: bool = ctx.obj["verbose"]

    identity_path = Path(identity)

    if lock:
        console.print(
            "[bold yellow]Warning:[/bold yellow] Flash lock is enabled. "
            "This operation is irreversible!"
        )
        if not click.confirm("Do you want to continue?"):
            console.print("Aborted.")
            sys.exit(0)

    console.print(f"[bold blue]Flashing device via {port}[/bold blue]")

    target_enum = FlashTarget.from_string(target)
    programmer = FlashProgrammer(port, target_enum, config.flash)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Connecting to device...", total=1)
        programmer.connect()
        progress.update(task, completed=1)

        task = progress.add_task("Erasing flash regions...", total=1)
        programmer.erase_regions()
        progress.update(task, completed=1)

        if bootloader:
            task = progress.add_task("Flashing bootloader...", total=1)
            programmer.flash_bootloader(Path(bootloader))
            progress.update(task, completed=1)

        if kernel:
            task = progress.add_task("Flashing kernel...", total=1)
            programmer.flash_kernel(Path(kernel))
            progress.update(task, completed=1)

        task = progress.add_task("Programming identity data...", total=1)
        programmer.program_identity(identity_path)
        progress.update(task, completed=1)

        if verify:
            task = progress.add_task("Verifying flash contents...", total=1)
            programmer.verify()
            progress.update(task, completed=1)

        if lock:
            task = progress.add_task("Locking flash regions...", total=1)
            programmer.lock_flash()
            progress.update(task, completed=1)

        programmer.disconnect()

    console.print("[bold green]✓[/bold green] Flash programming complete")


@main.command()
@click.option("--port", "-p", required=True, help="Serial port or debug probe")
@click.option(
    "--target",
    "-t",
    type=click.Choice(["stm32h7", "stm32u5", "riscv"]),
    required=True,
    help="Target platform",
)
@click.option("--identity", "-i", type=click.Path(exists=True), required=True, help="Expected identity data")
@click.option("--full", is_flag=True, help="Perform full verification including crypto tests")
@click.pass_context
def verify(
    ctx: click.Context,
    port: str,
    target: str,
    identity: str,
    full: bool,
) -> None:
    """Verify device provisioning and identity."""
    config: ProvisioningConfig = ctx.obj["config"]
    verbose: bool = ctx.obj["verbose"]

    identity_path = Path(identity)

    console.print(f"[bold blue]Verifying device provisioning via {port}[/bold blue]")

    target_enum = FlashTarget.from_string(target)
    verifier = ProvisioningVerifier(port, target_enum, config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Connecting to device...", total=1)
        verifier.connect()
        progress.update(task, completed=1)

        task = progress.add_task("Reading device identity...", total=1)
        device_identity = verifier.read_identity()
        progress.update(task, completed=1)

        task = progress.add_task("Verifying identity commitment...", total=1)
        result = verifier.verify_identity(identity_path, device_identity)
        progress.update(task, completed=1)

        if full:
            task = progress.add_task("Running cryptographic self-tests...", total=1)
            crypto_result = verifier.verify_crypto()
            progress.update(task, completed=1)

            task = progress.add_task("Verifying flash integrity...", total=1)
            flash_result = verifier.verify_flash()
            progress.update(task, completed=1)

        verifier.disconnect()

    # Display results
    table = Table(title="Verification Results")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    table.add_row(
        "Identity Commitment",
        "✓ PASS" if result.identity_valid else "✗ FAIL",
        result.identity_details,
    )

    if full:
        table.add_row(
            "Cryptographic Tests",
            "✓ PASS" if crypto_result.passed else "✗ FAIL",
            crypto_result.details,
        )
        table.add_row(
            "Flash Integrity",
            "✓ PASS" if flash_result.passed else "✗ FAIL",
            flash_result.details,
        )

    console.print(table)

    if result.identity_valid and (not full or (crypto_result.passed and flash_result.passed)):
        console.print("[bold green]✓[/bold green] Device provisioning verified successfully")
        sys.exit(0)
    else:
        console.print("[bold red]✗[/bold red] Device provisioning verification failed")
        sys.exit(1)


@main.command()
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["yaml", "json"]), default="yaml", help="Output format")
def init_config(output: str, fmt: str) -> None:
    """Generate a default configuration file."""
    from .config import generate_default_config

    output_path = Path(output)
    config_content = generate_default_config(fmt)

    with open(output_path, "w") as f:
        f.write(config_content)

    console.print(f"[bold green]✓[/bold green] Configuration file created at {output_path}")


@main.command()
def list_devices() -> None:
    """List connected debug probes and serial ports."""
    import serial.tools.list_ports

    console.print("[bold blue]Available Serial Ports:[/bold blue]")
    ports = serial.tools.list_ports.comports()

    if not ports:
        console.print("  No serial ports found")
    else:
        table = Table()
        table.add_column("Port", style="cyan")
        table.add_column("Description")
        table.add_column("Hardware ID")

        for port in ports:
            table.add_row(port.device, port.description, port.hwid)

        console.print(table)


if __name__ == "__main__":
    main()
