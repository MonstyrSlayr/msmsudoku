import os
import shutil
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import tempfile
import requests
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import textwrap

def wrap_text(text, font, max_width, draw):
    words = text.split()
    lines = []
    current = ""

    for word in words:
        test = current + (" " if current else "") + word

        bbox = draw.textbbox((0, 0), test, font=font)
        width = bbox[2] - bbox[0]

        if width <= max_width:
            current = test
        else:
            if current:
                lines.append(current)
            current = word

    if current:
        lines.append(current)

    return lines

def create_card_image(name, author, image_link, hex_code, directory):
    WIDTH = 1280
    HEIGHT = 720
    TITLE = "MSM Sudoku"

    OUTLINE_THICKNESS = 24
    max_text_width = WIDTH - 120

    # Create vertical dark grey gradient background
    background = Image.new("RGB", (WIDTH, HEIGHT))
    draw = ImageDraw.Draw(background)

    top_color = (35, 35, 35)
    bottom_color = (15, 15, 15)

    for y in range(HEIGHT):
        t = y / HEIGHT

        r = int(top_color[0] * (1 - t) + bottom_color[0] * t)
        g = int(top_color[1] * (1 - t) + bottom_color[1] * t)
        b = int(top_color[2] * (1 - t) + bottom_color[2] * t)

        draw.line([(0, y), (WIDTH, y)], fill=(r, g, b))

    # Draw outline
    draw.rectangle(
        [
            OUTLINE_THICKNESS // 2,
            OUTLINE_THICKNESS // 2,
            WIDTH - OUTLINE_THICKNESS // 2 - 1,
            HEIGHT - OUTLINE_THICKNESS // 2 - 1
        ],
        outline=hex_code,
        width=OUTLINE_THICKNESS
    )

    # Download image temporarily
    response = requests.get(image_link)
    response.raise_for_status()

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    temp_file.write(response.content)
    temp_file.close()

    try:
        # Load image
        cover = Image.open(temp_file.name).convert("RGBA")

        # Resize image while preserving aspect ratio
        max_image_width = 128 + 64
        max_image_height = 128 + 64

        scale = min(
            max_image_width / cover.width,
            max_image_height / cover.height
        )

        new_width = int(cover.width * scale)
        new_height = int(cover.height * scale)

        cover = cover.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Fonts
        try:
            title_font = ImageFont.truetype("arial.ttf", 80)
            name_font = ImageFont.truetype("arial.ttf", 60)
            author_font = ImageFont.truetype("arial.ttf", 48)
        except:
            title_font = ImageFont.load_default()
            name_font = ImageFont.load_default()
            author_font = ImageFont.load_default()

        # Measure text
        title_bbox = draw.textbbox((0, 0), TITLE, font=title_font)
        name_bbox = draw.textbbox((0, 0), name, font=name_font)
        author_bbox = draw.textbbox((0, 0), author, font=author_font)

        title_width = title_bbox[2] - title_bbox[0]
        title_height = title_bbox[3] - title_bbox[1]

        name_lines = wrap_text(
            name,
            name_font,
            max_text_width,
            draw
        )

        line_spacing = 10

        name_line_heights = []
        name_line_widths = []

        for line in name_lines:
            bbox = draw.textbbox((0, 0), line, font=name_font)

            line_widths = bbox[2] - bbox[0]
            line_heights = bbox[3] - bbox[1]

            name_line_widths.append(line_widths)
            name_line_heights.append(line_heights)

        total_name_height = (
            sum(name_line_heights) +
            line_spacing * (len(name_lines) - 1)
        )

        author_width = author_bbox[2] - author_bbox[0]
        author_height = author_bbox[3] - author_bbox[1]

        spacing = 48

        total_height = (
            cover.height +
            spacing +
            total_name_height +
            spacing +
            author_height +
            spacing +
            title_height
        )

        start_y = (HEIGHT - total_height) // 2

        # Draw title
        draw.text(
            ((WIDTH - title_width) // 2, start_y),
            TITLE,
            fill="white",
            font=title_font
        )

        current_y = start_y + title_height + spacing

        # Draw name
        for i, line in enumerate(name_lines):
            line_width = name_line_widths[i]
            line_height = name_line_heights[i]

            draw.text(
                ((WIDTH - line_width) // 2, current_y),
                line,
                fill="white",
                font=name_font
            )

            current_y += line_height + line_spacing

        current_y += spacing

        # Draw author
        draw.text(
            ((WIDTH - author_width) // 2, current_y),
            author,
            fill="white",
            font=author_font
        )

        current_y += author_height + spacing

        # Paste image
        image_x = (WIDTH - cover.width) // 2

        background.paste(
            cover,
            (image_x, current_y),
            cover
        )

        # Ensure output directory exists
        os.makedirs(directory, exist_ok=True)

        output_path = os.path.join(directory, f"thumb.jpg")

        # Save image
        background.save(output_path)

        return output_path

    finally:
        # Delete temporary downloaded image
        if os.path.exists(temp_file.name):
            os.remove(temp_file.name)

# Utility: convert string <-> bytes
def str_to_buf(string):
    return string.encode("utf-8")

def buf_to_str(buf):
    return buf.decode("utf-8")

# Utility: derive a crypto key from a password
def derive_key(password):
    password_bytes = str_to_buf(password)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=str_to_buf("sudoku-salt"),
        iterations=100000,
        backend=default_backend()
    )

    return kdf.derive(password_bytes)

def decrypt_file(file_path, secret_key):
    key = derive_key(secret_key)

    with open(file_path, "rb") as f:
        data = f.read()

    # Extract IV (first 12 bytes)
    iv = data[:12]
    encrypted_data = data[12:]

    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(
        iv,
        encrypted_data,
        None
    )

    json_str = buf_to_str(decrypted)
    return json.loads(json_str)

def list_files(directory, output_file):
    files = os.listdir(directory)
    with open(output_file, 'w') as f:
        for file in files:
            f.write(f"{file}\n")
    return files

if __name__ == "__main__":
    files = list_files("./data", "./data_files.txt")

    os.makedirs("./play", exist_ok=True)

    for file_name in files:
        folder_path = os.path.join("./play", file_name.replace(".sud", ""))

        # Delete if it already exists
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)

        os.makedirs(folder_path)

        # decrypt sud
        da_json = decrypt_file(os.path.join("./data", file_name), "amongUsInRealLifeSusSus")

        create_card_image(str(da_json["metadata"]["name"]), str(da_json["metadata"]["author"]), str(da_json["metadata"]["img"]), str(da_json["metadata"]["color"]), folder_path)

        # Copy template
        with open("./play/template.html", "r", encoding="utf-8") as f:
            template_content = f.read()

        replaced = template_content.replace("{name}", str(da_json["metadata"]["name"]))
        replaced = replaced.replace("{author}", str(da_json["metadata"]["author"]))
        replaced = replaced.replace("{friendCode}", str(da_json["metadata"]["friendCode"]))
        replaced = replaced.replace("{img}", str(da_json["metadata"]["img"]))
        replaced = replaced.replace("{filename}", file_name.replace(".sud", ""))

        # Always save as index.html
        dest_file = os.path.join(folder_path, "index.html")

        with open(dest_file, "w", encoding="utf-8") as out:
            out.write(replaced)

        print(f"Created folder: {folder_path}")
