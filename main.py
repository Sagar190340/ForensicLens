import os
import hashlib
import exifread
from PIL import Image, ImageChops, ImageEnhance
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

console = Console()

class ForensicTool:
    def __init__(self, target):
        self.target = target
        
    def get_hashes(self):
        """Generates MD5 and SHA-256 for integrity."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(self.target, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()

    def get_exif(self):
        """Extracts EXIF metadata."""
        with open(self.target, 'rb') as f:
            tags = exifread.process_file(f, details=False)
        return {k: v for k, v in tags.items() if k not in ['JPEGThumbnail', 'TIFFThumbnail']}

    def run_ela(self, quality=90):
        """Performs Error Level Analysis."""
        ela_filename = "ela_result.jpg"
        original = Image.open(self.target).convert('RGB')
        original.save(ela_filename, 'JPEG', quality=quality)
        
        temporary = Image.open(ela_filename)
        ela_image = ImageChops.difference(original, temporary)
        
        extrema = ela_image.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        if max_diff == 0: max_diff = 1
        scale = 255.0 / max_diff
        
        ela_image = ImageEnhance.Brightness(ela_image).enhance(scale)
        ela_image.save("FORENSIC_ANALYSIS.png")
        os.remove(ela_filename)
        return "FORENSIC_ANALYSIS.png"

def run():
    console.print(Panel.fit("🔍 IMAGE FORENSIC TOOLKIT", style="bold green", subtitle="v1.0.0"))
    img_path = input("Enter Image Path (e.g., sample.jpg): ").strip()

    if not os.path.exists(img_path):
        console.print("[red]Error: File not found![/red]")
        return

    forensic = ForensicTool(img_path)

    # 1. Hashing
    md5, sha256 = forensic.get_hashes()
    hash_table = Table(title="File Integrity (Hashes)")
    hash_table.add_column("Algorithm", style="cyan")
    hash_table.add_column("Hash Value", style="magenta")
    hash_table.add_row("MD5", md5)
    hash_table.add_row("SHA-256", sha256)
    console.print(hash_table)

    # 2. Metadata
    tags = forensic.get_exif()
    if tags:
        meta_table = Table(title="Metadata (EXIF)")
        meta_table.add_column("Tag", style="yellow")
        meta_table.add_column("Value", style="white")
        for k, v in list(tags.items())[:15]: # Limiting to 15 for clean view
            meta_table.add_row(str(k), str(v))
        console.print(meta_table)
    else:
        console.print("[yellow]No EXIF metadata found.[/yellow]")

    # 3. ELA
    console.print("\n[blue]Running Error Level Analysis (ELA)...[/blue]")
    for _ in track(range(10), description="Processing..."):
        pass
    res = forensic.run_ela()
    console.print(f"[bold green]ELA Analysis saved as: {res}[/bold green]")

if __name__ == "__main__":
    run()
