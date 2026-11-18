import os
import subprocess
import time
from PIL import Image

states = [
    ("initial", "1. Arup Deepfake Video Call Active — $250,000 Demanded"),
    ("attack1", "2. Attack 1: Fake CFO on Call — Blocked (Key Unenrolled)"),
    ("attack2", "3. Attack 2: Swapped Bank Account — Flagged in Red on Prime"),
    ("attack3", "4. Attack 3: Amount Altered ($25k to $250k) — Blocked (Hash Mismatch)"),
    ("attack4", "5. Attack 4: Replay Attack — Blocked (Nonce Expired)"),
    ("honest", "6. Honest Payment: $25,000 to Autodesk — Verified & Approved"),
    ("release", "7. Bank Wire Released — Signed Audit Trail Recorded")
]

frames = []
tmp_dir = "/tmp/truecall_frames"
os.makedirs(tmp_dir, exist_ok=True)

chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

print("🎬 Capturing TrueCall demo sequence frames via Headless Chrome...")

for state, label in states:
    url = f"http://localhost:3001/?state={state}"
    out_png = os.path.join(tmp_dir, f"{state}.png")
    
    cmd = [
        chrome_bin,
        "--headless",
        "--disable-gpu",
        "--window-size=1200,760",
        f"--screenshot={out_png}",
        url
    ]
    
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(out_png):
        img = Image.open(out_png)
        # Resize slightly for smooth email size
        img = img.resize((1080, 684), Image.Resampling.LANCZOS)
        frames.append(img)
        print(f"  ✓ Captured: {label}")

if frames:
    gif_path = "/Users/pushpendra/Documents/truecall/truecall-demo.gif"
    print(f"\n💾 Compiling animated demo video: {gif_path} ...")
    
    # 2.2 seconds per frame, loop infinitely
    frames[0].save(
        gif_path,
        save_all=True,
        append_images=frames[1:],
        duration=[2400, 2400, 2600, 2400, 2400, 2400, 2800],
        loop=0,
        optimize=True
    )
    
    file_size_mb = os.path.getsize(gif_path) / (1024 * 1024)
    print(f"🎉 Demo GIF generated successfully! Size: {file_size_mb:.2f} MB")
else:
    print("❌ Failed to capture frames.")

