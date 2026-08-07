import os
import sys
import time
import math
from PIL import Image, ImageDraw, ImageFont
import cv2
import numpy as np
from playwright.sync_api import sync_playwright

def create_annotations(frame_np, phase_title, step_caption, highlight_rect=None, step_index=1, total_steps=5):
    """
    Renders HD visual annotations, lower-third phase banner, subtitle caption,
    and pulsing highlight rectangle onto a 1920x1080 frame.
    """
    img = Image.fromarray(cv2.cvtColor(frame_np, cv2.COLOR_BGR2RGB))
    draw = ImageDraw.Draw(img, 'RGBA')
    width, height = img.size

    # Load system fonts with fallbacks
    try:
        font_banner = ImageFont.truetype("arialbd.ttf", 26)
        font_caption = ImageFont.truetype("arial.ttf", 22)
        font_badge = ImageFont.truetype("arialbd.ttf", 18)
    except Exception:
        font_banner = ImageFont.load_default()
        font_caption = ImageFont.load_default()
        font_badge = ImageFont.load_default()

    # 1. Top Bar / Header Branding Overlay
    draw.rectangle([(0, 0), (width, 45)], fill=(10, 16, 26, 230))
    draw.text((20, 10), "PHANTOMNET SENTINEL V3 — LIVE DEMONSTRATION", fill=(0, 229, 255, 255), font=font_badge)

    # Step progress badge
    step_str = f"STEP {step_index} OF {total_steps}"
    draw.rectangle([(width - 160, 8), (width - 20, 36)], fill=(30, 41, 59, 230), outline=(0, 229, 255, 255))
    draw.text((width - 145, 12), step_str, fill=(255, 255, 255, 255), font=font_badge)

    # 2. Lower-Third Phase Banner (Glassmorphism dark card)
    banner_y = height - 120
    draw.rectangle([(30, banner_y), (width - 30, height - 30)], fill=(15, 23, 42, 230), outline=(56, 189, 248, 255), width=2)

    # Phase Title
    draw.text((50, banner_y + 12), phase_title.upper(), fill=(56, 189, 248, 255), font=font_banner)
    # Step Caption / Subtitle
    draw.text((50, banner_y + 48), step_caption, fill=(241, 245, 249, 255), font=font_caption)

    # 3. Optional Highlight Rectangle around target UI elements
    if highlight_rect:
        x1, y1, x2, y2 = highlight_rect
        # Draw translucent filled overlay around rectangle
        draw.rectangle([(x1, y1), (x2, y2)], fill=(0, 229, 255, 30), outline=(0, 229, 255, 255), width=3)
        # Draw corner accents
        c_len = 15
        draw.line([(x1, y1), (x1 + c_len, y1)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x1, y1), (x1, y1 + c_len)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x2, y2), (x2 - c_len, y2)], fill=(255, 255, 255, 255), width=4)
        draw.line([(x2, y2), (x2, y2 - c_len)], fill=(255, 255, 255, 255), width=4)

    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

def record_sentinel_v3_demo():
    print("[INFO] Starting Sentinel V3 1080p Screen Recording & Annotation Pipeline...")

    frames = []
    fps = 10  # 10 fps capture rate for crisp animation
    target_width, target_height = 1920, 1080

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': target_width, 'height': target_height},
            device_scale_factor=1.0
        )
        page = context.new_page()

        def capture_frames(duration_sec, phase_title, caption, highlight=None, step_idx=1):
            count = int(duration_sec * fps)
            for _ in range(count):
                screenshot_bytes = page.screenshot(type='png')
                nparr = np.frombuffer(screenshot_bytes, np.uint8)
                img_np = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if img_np.shape[1] != target_width or img_np.shape[0] != target_height:
                    img_np = cv2.resize(img_np, (target_width, target_height))
                annotated = create_annotations(img_np, phase_title, caption, highlight, step_index=step_idx, total_steps=5)
                frames.append(annotated)
                time.sleep(1.0 / fps)

        # -------------------------------------------------------------
        # PHASE 1: Attack Vector Simulation
        # -------------------------------------------------------------
        print("[PHASE 1] Recording Phase 1: Attack Vector Simulation...")
        page.goto("http://localhost:5173/hunting", wait_until="domcontentloaded")
        page.wait_for_timeout(1500)
        capture_frames(
            duration_sec=3.0,
            phase_title="Phase 1: Attack Vector Simulation",
            caption="High-frequency SSH password guessing attack (T1110.001) captured from 192.168.1.105.",
            highlight=[80, 140, 1840, 320],
            step_idx=1
        )

        # -------------------------------------------------------------
        # PHASE 2: AI Detection & MITRE Mapping
        # -------------------------------------------------------------
        print("[PHASE 2] Recording Phase 2: AI Detection & MITRE Mapping...")
        page.goto("http://localhost:5173/sentinel", wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 2: AI Detection & MITRE Mapping",
            caption="ML Anomaly Engine calculates 95/100 threat score and maps event to MITRE ATT&CK Matrix.",
            highlight=[80, 120, 1840, 480],
            step_idx=2
        )

        # -------------------------------------------------------------
        # PHASE 3: Playbook & Rule Generation
        # -------------------------------------------------------------
        print("[PHASE 3] Recording Phase 3: Playbook & Rule Generation...")
        # Hover over first card or click it
        card = page.locator(".playbook-card").first
        if card.count() > 0:
            card.click()
            page.wait_for_timeout(1500)
        
        capture_frames(
            duration_sec=4.0,
            phase_title="Phase 3: Playbook & Rule Generation",
            caption="Sentinel V3 auto-synthesizes Snort alert rules, Sigma YAML signatures, and LLM narrative.",
            highlight=[180, 80, 1740, 950],
            step_idx=3
        )

        # -------------------------------------------------------------
        # PHASE 4: Analyst Review & Approval Workflow
        # -------------------------------------------------------------
        print("[PHASE 4] Recording Phase 4: Analyst Review & Approval Workflow...")
        approve_btn = page.locator(".btn-approve").first
        if approve_btn.count() > 0:
            approve_btn.click()
            page.wait_for_timeout(800)

            # Type analyst name
            input_box = page.locator("#analyst-name-input")
            if input_box.count() > 0:
                input_box.fill("analyst_admin")
                page.wait_for_timeout(500)

            capture_frames(
                duration_sec=2.5,
                phase_title="Phase 4: SOC Analyst Review & Approval",
                caption="Analyst inspects automated remediation rules and submits digital authorization signature.",
                highlight=[550, 250, 1370, 750],
                step_idx=4
            )

            confirm_btn = page.locator(".btn-confirm-approve").first
            if confirm_btn.count() > 0:
                confirm_btn.click()
                page.wait_for_timeout(1200)

        capture_frames(
            duration_sec=2.5,
            phase_title="Phase 4: Status Transition Verified",
            caption="Playbook status transitions to 'Approved'. Mitigation signatures locked for deployment.",
            highlight=[180, 80, 1740, 950],
            step_idx=4
        )

        # -------------------------------------------------------------
        # PHASE 5: Interoperability & STIX Export
        # -------------------------------------------------------------
        print("[PHASE 5] Recording Phase 5: Interoperability & STIX Export...")
        export_btn = page.locator("#playbook-viewer-export-btn").first
        if export_btn.count() > 0:
            export_btn.click()
            page.wait_for_timeout(800)

        capture_frames(
            duration_sec=3.5,
            phase_title="Phase 5: Threat Intelligence Export",
            caption="Exporting executive PDF incident report and standardized STIX 2.1 JSON bundle.",
            highlight=[1300, 150, 1720, 420],
            step_idx=5
        )

        browser.close()

    print(f"[INFO] Total captured frames: {len(frames)}")

    # -------------------------------------------------------------
    # Render Video Deliverables (MP4 and WebP)
    # -------------------------------------------------------------
    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "demos")
    os.makedirs(output_dir, exist_ok=True)

    mp4_path = os.path.join(output_dir, "sentinel_v3_demo.mp4")
    webp_path = os.path.join(output_dir, "sentinel_v3_demo.webp")

    # Artifact directory path
    artifact_dir = r"C:\Users\manid\.gemini\antigravity-ide\brain\f21840b8-3179-43f7-aa6a-78b6da97aac4"
    artifact_mp4 = os.path.join(artifact_dir, "sentinel_v3_demo.mp4")
    artifact_webp = os.path.join(artifact_dir, "sentinel_v3_demo.webp")

    # 1. Output MP4 using OpenCV VideoWriter
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(mp4_path, fourcc, fps, (target_width, target_height))
    for frame in frames:
        out.write(frame)
    out.release()
    print(f"[OK] Exported MP4 Demo: {mp4_path} ({os.path.getsize(mp4_path)} bytes)")

    # Copy MP4 to artifacts
    if os.path.exists(artifact_dir):
        with open(mp4_path, 'rb') as f_src, open(artifact_mp4, 'wb') as f_dst:
            f_dst.write(f_src.read())
        print(f"[OK] Copied MP4 to Artifacts: {artifact_mp4}")

    # 2. Output Animated WebP preview using Pillow
    print("[INFO] Rendering Animated WebP preview...")
    pil_frames = []
    # Subsample frames for lightweight webp
    subsampled = frames[::2]
    for frame in subsampled:
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        # Resize slightly for optimized preview size (1280x720)
        img_pil = Image.fromarray(rgb).resize((1280, 720), Image.Resampling.LANCZOS)
        pil_frames.append(img_pil)

    if pil_frames:
        pil_frames[0].save(
            webp_path,
            save_all=True,
            append_images=pil_frames[1:],
            duration=int(2000 / fps),
            loop=0
        )
        print(f"[OK] Exported Animated WebP: {webp_path} ({os.path.getsize(webp_path)} bytes)")

        if os.path.exists(artifact_dir):
            with open(webp_path, 'rb') as f_src, open(artifact_webp, 'wb') as f_dst:
                f_dst.write(f_src.read())
            print(f"[OK] Copied Animated WebP to Artifacts: {artifact_webp}")

    print("[SUCCESS] Sentinel V3 Demonstration Video Production Complete!")

if __name__ == "__main__":
    record_sentinel_v3_demo()
