import os
import subprocess
import imageio_ffmpeg

ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
tmp_dir = "/tmp/truecall_frames"
mp4_path = "/Users/pushpendra/Documents/truecall/truecall-demo.mp4"

# Sequence of scenes with durations
scenes = [
    ("initial.png", 2.5),
    ("attack1.png", 2.5),
    ("attack2.png", 3.0),
    ("attack3.png", 2.5),
    ("attack4.png", 2.5),
    ("honest.png", 2.5),
    ("release.png", 3.0)
]

concat_list = "/tmp/concat_scenes.txt"
with open(concat_list, "w") as f:
    for filename, dur in scenes:
        full_path = os.path.join(tmp_dir, filename)
        f.write(f"file '{full_path}'\n")
        f.write(f"duration {dur}\n")
    # Repeat last frame to avoid truncation in ffmpeg concat demuxer
    last_file = os.path.join(tmp_dir, scenes[-1][0])
    f.write(f"file '{last_file}'\n")

print(f"🎬 Compiling H.264 MP4 demo video via {ffmpeg_exe}...")

cmd = [
    ffmpeg_exe,
    "-y",
    "-f", "concat",
    "-safe", "0",
    "-i", concat_list,
    "-vf", "scale=1280:-2,format=yuv420p",
    "-c:v", "libx264",
    "-preset", "medium",
    "-crf", "20",
    "-r", "30",
    "-movflags", "+faststart",
    mp4_path
]

res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if os.path.exists(mp4_path):
    size_mb = os.path.getsize(mp4_path) / (1024 * 1024)
    print(f"🎉 Success! Generated: {mp4_path} ({size_mb:.2f} MB)")
else:
    print("❌ Failed to generate MP4:")
    print(res.stderr)

