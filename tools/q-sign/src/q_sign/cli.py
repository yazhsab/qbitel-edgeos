"""Command-line interface for Qbitel EdgeOS signing tool."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .signer import FirmwareSigner, SigningKey, SignatureAlgorithm
from .manifest import ManifestBuilder, ImageType
from .verify import SignatureVerifier
from .package import PackageBuilder

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="q-sign")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Qbitel EdgeOS Firmware Signing Tool.

    Sign firmware images with post-quantum cryptographic signatures.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@main.command()
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(["dilithium3", "falcon512", "falcon1024"]),
    default="dilithium3",
    help="Signature algorithm",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output key file path")
@click.option("--key-id", "-k", required=True, help="Key identifier")
@click.option("--purpose", "-p", type=click.Choice(["firmware", "update", "attestation"]), default="firmware", help="Key purpose")
@click.pass_context
def keygen(
    ctx: click.Context,
    algorithm: str,
    output: str,
    key_id: str,
    purpose: str,
) -> None:
    """Generate a new signing key pair."""
    verbose: bool = ctx.obj["verbose"]
    output_path = Path(output)

    console.print(f"[bold blue]Generating {algorithm} signing key[/bold blue]")

    algo = SignatureAlgorithm.from_string(algorithm)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Generating {algorithm} keypair...", total=1)
        key = SigningKey.generate(algo, key_id, purpose)
        progress.update(task, completed=1)

        task = progress.add_task("Saving key files...", total=1)
        key.save(output_path)
        progress.update(task, completed=1)

    console.print(f"[bold green]✓[/bold green] Signing key saved to {output_path}")

    if verbose:
        table = Table(title="Key Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Algorithm", algorithm)
        table.add_row("Key ID", key_id)
        table.add_row("Purpose", purpose)
        table.add_row("Public Key Hash", key.public_key_hash()[:16])
        console.print(table)


@main.command()
@click.option("--image", "-i", type=click.Path(exists=True), required=True, help="Firmware image to sign")
@click.option("--key", "-k", type=click.Path(exists=True), required=True, help="Signing key file")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output signed image path")
@click.option(
    "--image-type",
    "-t",
    type=click.Choice(["bootloader", "kernel", "application"]),
    required=True,
    help="Image type",
)
@click.option("--version", "-V", required=True, help="Firmware version (semver)")
@click.option("--rollback-version", type=int, default=1, help="Monotonic rollback version")
@click.option("--hardware-version", default="1.0.0", help="Minimum hardware version")
@click.pass_context
def sign(
    ctx: click.Context,
    image: str,
    key: str,
    output: str,
    image_type: str,
    version: str,
    rollback_version: int,
    hardware_version: str,
) -> None:
    """Sign a firmware image."""
    verbose: bool = ctx.obj["verbose"]

    image_path = Path(image)
    key_path = Path(key)
    output_path = Path(output)

    console.print(f"[bold blue]Signing {image_path.name}[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading signing key...", total=1)
        signing_key = SigningKey.load(key_path)
        progress.update(task, completed=1)

        task = progress.add_task("Reading firmware image...", total=1)
        with open(image_path, "rb") as f:
            image_data = f.read()
        progress.update(task, completed=1)

        task = progress.add_task("Building manifest...", total=1)
        builder = ManifestBuilder()
        manifest = builder.build(
            image_data=image_data,
            image_type=ImageType.from_string(image_type),
            version=version,
            rollback_version=rollback_version,
            hardware_version=hardware_version,
            signer_key_id=signing_key.key_id,
        )
        progress.update(task, completed=1)

        task = progress.add_task("Signing manifest...", total=1)
        signer = FirmwareSigner(signing_key)
        signed_manifest = signer.sign_manifest(manifest)
        progress.update(task, completed=1)

        task = progress.add_task("Writing signed image...", total=1)
        signed_image = signer.create_signed_image(image_data, signed_manifest)
        with open(output_path, "wb") as f:
            f.write(signed_image)
        progress.update(task, completed=1)

    console.print(f"[bold green]✓[/bold green] Signed image saved to {output_path}")

    if verbose:
        table = Table(title="Signature Details")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Image Size", f"{len(image_data)} bytes")
        table.add_row("Image Hash", manifest.image_hash[:32].hex() + "...")
        table.add_row("Version", version)
        table.add_row("Rollback Version", str(rollback_version))
        table.add_row("Algorithm", signing_key.algorithm.value)
        table.add_row("Signature Size", f"{len(signed_manifest.signature)} bytes")
        console.print(table)


@main.command()
@click.option("--image", "-i", type=click.Path(exists=True), required=True, help="Signed firmware image")
@click.option("--key", "-k", type=click.Path(exists=True), help="Public key file (optional, uses embedded)")
@click.option("--strict", is_flag=True, help="Fail on any warning")
@click.pass_context
def verify(
    ctx: click.Context,
    image: str,
    key: Optional[str],
    strict: bool,
) -> None:
    """Verify a signed firmware image."""
    verbose: bool = ctx.obj["verbose"]

    image_path = Path(image)

    console.print(f"[bold blue]Verifying {image_path.name}[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Reading signed image...", total=1)
        with open(image_path, "rb") as f:
            signed_data = f.read()
        progress.update(task, completed=1)

        public_key = None
        if key:
            task = progress.add_task("Loading public key...", total=1)
            public_key = SigningKey.load_public(Path(key))
            progress.update(task, completed=1)

        task = progress.add_task("Verifying signature...", total=1)
        verifier = SignatureVerifier()
        result = verifier.verify(signed_data, public_key)
        progress.update(task, completed=1)

    # Display results
    table = Table(title="Verification Results")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    table.add_row(
        "Manifest Magic",
        "✓ PASS" if result.magic_valid else "✗ FAIL",
        result.magic_details,
    )
    table.add_row(
        "Manifest Structure",
        "✓ PASS" if result.structure_valid else "✗ FAIL",
        result.structure_details,
    )
    table.add_row(
        "Image Hash",
        "✓ PASS" if result.hash_valid else "✗ FAIL",
        result.hash_details,
    )
    table.add_row(
        "Signature",
        "✓ PASS" if result.signature_valid else "✗ FAIL",
        result.signature_details,
    )
    table.add_row(
        "Rollback Protection",
        "✓ PASS" if result.rollback_valid else "⚠ WARN",
        result.rollback_details,
    )

    console.print(table)

    if result.is_valid():
        console.print("[bold green]✓[/bold green] Signature verification successful")
        sys.exit(0)
    elif result.has_warnings() and not strict:
        console.print("[bold yellow]⚠[/bold yellow] Verification passed with warnings")
        sys.exit(0)
    else:
        console.print("[bold red]✗[/bold red] Signature verification failed")
        sys.exit(1)


@main.command()
@click.option("--bootloader", "-b", type=click.Path(exists=True), help="Signed bootloader image")
@click.option("--kernel", "-k", type=click.Path(exists=True), required=True, help="Signed kernel image")
@click.option("--application", "-a", type=click.Path(exists=True), help="Signed application image")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output package path")
@click.option("--version", "-V", required=True, help="Package version")
@click.option("--target", "-t", type=click.Choice(["stm32h7", "stm32u5", "riscv"]), required=True, help="Target platform")
@click.option("--signing-key", type=click.Path(exists=True), required=True, help="Key for package signing")
@click.pass_context
def package(
    ctx: click.Context,
    bootloader: Optional[str],
    kernel: str,
    application: Optional[str],
    output: str,
    version: str,
    target: str,
    signing_key: str,
) -> None:
    """Create an update package from signed images."""
    verbose: bool = ctx.obj["verbose"]
    output_path = Path(output)

    console.print(f"[bold blue]Creating update package v{version}[/bold blue]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading signing key...", total=1)
        key = SigningKey.load(Path(signing_key))
        progress.update(task, completed=1)

        builder = PackageBuilder(key, target)

        if bootloader:
            task = progress.add_task("Adding bootloader...", total=1)
            builder.add_bootloader(Path(bootloader))
            progress.update(task, completed=1)

        task = progress.add_task("Adding kernel...", total=1)
        builder.add_kernel(Path(kernel))
        progress.update(task, completed=1)

        if application:
            task = progress.add_task("Adding application...", total=1)
            builder.add_application(Path(application))
            progress.update(task, completed=1)

        task = progress.add_task("Building package...", total=1)
        package_data = builder.build(version)
        progress.update(task, completed=1)

        task = progress.add_task("Writing package...", total=1)
        with open(output_path, "wb") as f:
            f.write(package_data)
        progress.update(task, completed=1)

    console.print(f"[bold green]✓[/bold green] Update package saved to {output_path}")

    if verbose:
        table = Table(title="Package Contents")
        table.add_column("Component", style="cyan")
        table.add_column("Size", style="green")
        if bootloader:
            table.add_row("Bootloader", f"{Path(bootloader).stat().st_size} bytes")
        table.add_row("Kernel", f"{Path(kernel).stat().st_size} bytes")
        if application:
            table.add_row("Application", f"{Path(application).stat().st_size} bytes")
        table.add_row("Total Package", f"{len(package_data)} bytes")
        console.print(table)


@main.command()
@click.option("--key", "-k", type=click.Path(exists=True), required=True, help="Key file")
@click.pass_context
def keyinfo(ctx: click.Context, key: str) -> None:
    """Display information about a signing key."""
    key_path = Path(key)

    console.print(f"[bold blue]Key Information: {key_path.name}[/bold blue]")

    try:
        signing_key = SigningKey.load(key_path)
        is_private = True
    except Exception:
        signing_key = SigningKey.load_public(key_path)
        is_private = False

    table = Table()
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Key ID", signing_key.key_id)
    table.add_row("Algorithm", signing_key.algorithm.value)
    table.add_row("Purpose", signing_key.purpose)
    table.add_row("Type", "Private + Public" if is_private else "Public Only")
    table.add_row("Public Key Size", f"{len(signing_key.public_key)} bytes")
    table.add_row("Public Key Hash", signing_key.public_key_hash())
    if signing_key.created_at:
        table.add_row("Created", signing_key.created_at.isoformat())

    console.print(table)


@main.command()
@click.option("--key", "-k", type=click.Path(exists=True), required=True, help="Private key file")
@click.option("--output", "-o", type=click.Path(), required=True, help="Output public key file")
def export_public(key: str, output: str) -> None:
    """Export public key from a private key file."""
    key_path = Path(key)
    output_path = Path(output)

    console.print(f"[bold blue]Exporting public key[/bold blue]")

    signing_key = SigningKey.load(key_path)
    signing_key.save_public(output_path)

    console.print(f"[bold green]✓[/bold green] Public key saved to {output_path}")


if __name__ == "__main__":
    main()
