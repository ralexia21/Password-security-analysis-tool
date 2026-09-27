import math
import time
import os
import tkinter as tk
from tkinter import ttk

def get_charset_size(password):

    lower = any(c.islower() for c in password)
    upper = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() for c in password)

    size = 0

    if lower:
        size += 26

    if upper:
        size += 26

    if digits:
        size += 10

    if symbols:
        size += 32

    return size


def password_score(password):

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2

    elif len(password) >= 8:
        score += 1

    else:
        feedback.append("Password is too short")

    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    if any(not c.isalnum() for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    return score, feedback


def calculate_entropy(password):

    charset_size = get_charset_size(password)

    if charset_size == 0:
        return 0

    entropy = len(password) * math.log2(charset_size)

    return entropy


def classify_entropy(entropy):

    if entropy < 40:
        return "Weak entropy"

    elif entropy < 60:
        return "Moderate entropy"

    elif entropy < 80:
        return "Strong entropy"

    else:
        return "Very strong entropy"


def estimate_crack_time(password):

    charset_size = get_charset_size(password)
    length = len(password)

    combinations = charset_size ** length

    guesses_per_second = 1e9

    seconds = combinations / guesses_per_second

    return seconds


def human_readable_time(seconds):

    minute = 60
    hour = 3600
    day = 86400
    month = day * 30
    year = day * 365
    century = year * 100

    if seconds < 1:
        return "Less than 1 second"

    elif seconds < minute:
        return f"{seconds:.2f} seconds"

    elif seconds < hour:
        return f"{seconds / minute:.2f} minutes"

    elif seconds < day:
        return f"{seconds / hour:.2f} hours"

    elif seconds < month:
        return f"{seconds / day:.2f} days"

    elif seconds < year:
        return f"{seconds / month:.2f} months"

    elif seconds < century:
        return f"{seconds / year:.2f} years"

    else:
        return f"{seconds / century:.2f} centuries"


def classify_time(seconds):

    minute = 60
    hour = 3600
    day = 86400
    year = 31536000
    century = year * 100

    if seconds < minute:
        return "Very Weak"

    elif seconds < day:
        return "Weak"

    elif seconds <= 3*day:
        return "Medium"

    elif seconds < year or seconds <4*day:
        return "Strong"

    elif seconds < century:
        return "Very Strong"

    else:
        return "Extremely Strong"


def final_analysis(score, entropy, seconds):

    if score <= 2 or entropy < 40:
        return "VERY WEAK PASSWORD"

    elif score <= 4 or entropy < 60:
        return "MODERATE PASSWORD"

    elif score >= 5 and entropy >= 60 and seconds > 31536000:
        return "STRONG PASSWORD"

    else:
        return "GOOD PASSWORD"


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_wordlist(relative_path, limit=None):

    passwords = []

    full_path = os.path.join(BASE_DIR, relative_path)

    try:

        with open(full_path, "r", encoding="utf-8", errors="ignore") as file:

            for i, line in enumerate(file):

                if limit and i >= limit:
                    break

                line = line.strip()

                if line:
                    passwords.append(line)

    except Exception as e:
        print("ERROR:", e)

    return passwords


common_passwords = load_wordlist("top10000000.txt")
rockyou_passwords = load_wordlist("rockyou-75.txt")
webhost_passwords = load_wordlist("webhost.txt")

keyboard_patterns = load_wordlist("Keyboard-Combinations.txt")
walk_patterns = load_wordlist("walk-the-line.txt")

def dictionary_attack(password):

    start = time.time()

    datasets = {

        "Top Common Passwords": common_passwords,
        "RockYou Dataset": rockyou_passwords,
        "Webhost Dataset": webhost_passwords
    }

    results = []

    for dataset_name, dataset in datasets.items():

        attempts = 0
        found = False

        for candidate in dataset:

            attempts += 1

            if candidate == password:

                end = time.time()

                results.append({
                    "dataset": dataset_name,
                    "found": True,
                    "attempts": attempts,
                    "time": end - start
                })

                found = True
                break

        if not found:

            end = time.time()

            results.append({
                "dataset": dataset_name,
                "found": False,
                "attempts": attempts,
                "time": end - start
            })

    return results


def keyboard_attack(password):

    start = time.time()

    datasets = {

        "Keyboard Combinations": keyboard_patterns,
        "Walk The Line": walk_patterns
    }

    results = []

    for dataset_name, dataset in datasets.items():

        attempts = 0
        found = False

        for candidate in dataset:

            attempts += 1

            if candidate == password:

                end = time.time()

                results.append({
                    "dataset": dataset_name,
                    "found": True,
                    "attempts": attempts,
                    "time": end - start
                })

                found = True
                break

        if not found:

            end = time.time()

            results.append({
                "dataset": dataset_name,
                "found": False,
                "attempts": attempts,
                "time": end - start
            })

    return results

window = tk.Tk()

window.title("Password Security Dashboard")
window.geometry("950x750")
window.configure(bg="#ff9d9d")

title = tk.Label(
    window,
    text="Password Security & Attack Analysis Dashboard",
    font=("Arial", 18, "bold"),
    fg="#fce5e5",
    bg="#ff9d9d"
)

title.pack(pady=15)

frame_input = tk.Frame(window, bg="#ff9d9d")

frame_input.pack(pady=10)

password_entry = tk.Entry(
    frame_input,
    width=40,
    font=("Arial", 14),
    show="*"
)

password_entry.pack(side=tk.LEFT, padx=10)

def get_risk_color(time_class):

    if time_class.startswith("Very Weak"):
        return "#ff0000"

    elif time_class.startswith("Weak"):
        return "#ff8800"

    elif time_class.startswith("Medium"):
        return "#ffff00"

    elif time_class.startswith("Strong"):
        return "#66ff66"

    elif time_class.startswith("Very Strong"):
        return "#00cc00"

    elif time_class.startswith("Extremely Strong"):
        return "#006600"

    else:
        return "white"


def run_analysis():

    password = password_entry.get()

    if not password:

        result_label.config(text="Please enter a password")

        return

    score, feedback = password_score(password)

    entropy = calculate_entropy(password)

    entropy_class = classify_entropy(entropy)

    seconds = estimate_crack_time(password)

    readable_time = human_readable_time(seconds)

    time_class = classify_time(seconds)

    final_result = final_analysis(score, entropy, seconds)

    dict_results = dictionary_attack(password)

    key_results = keyboard_attack(password)

    result_text = f"""

SCORE: {score}/6

ENTROPY: {entropy:.2f} bits
ENTROPY CLASSIFICATION: {entropy_class}

CRACK TIME: {readable_time}
CRACK TIME CLASSIFICATION: {time_class}

FINAL RESULT: {final_result}
"""

    result_label.config(text=result_text)

    risk_color = get_risk_color(time_class)

    color_canvas.delete("all")

    color_canvas.create_rectangle(
    5,
    5,
    55,
    55,
    fill=risk_color,
    outline="white",
    width=2
)

    attack_text = ""

    for r in dict_results:

        attack_text += (
            f"[DICTIONARY] {r['dataset']} "
            f"-> {'FOUND' if r['found'] else 'NOT FOUND'} "
            f"({r['attempts']} tries)\n"
        )

    for r in key_results:

        attack_text += (
            f"[KEYBOARD] {r['dataset']} "
            f"-> {'FOUND' if r['found'] else 'NOT FOUND'} "
            f"({r['attempts']} tries)\n"
        )

    attack_label.config(text=attack_text)

    feedback_text = ""

    if feedback:

        for item in feedback:

            feedback_text += f"- {item}\n"

    else:

        feedback_text = "Excellent password structure."

    feedback_label.config(text=feedback_text)

analyze_btn = tk.Button(
    frame_input,
    text="Analyze",
    command=run_analysis,
    bg="#f7c2c2",
    fg="white",
    font=("Arial", 12, "bold")
)

analyze_btn.pack(side=tk.LEFT)

result_label = tk.Label(
    window,
    text="",
    font=("Consolas", 12),
    fg="#fce5e5",
    bg="#ffb7b7",
    justify="left",
    padx=20,
    pady=20,
    relief="groove",
    bd=3
)

result_label.pack(pady=15)

color_canvas = tk.Canvas(
    window,
    width=60,
    height=60,
    bg="#ff9d9d",
    highlightthickness=0
)

color_canvas.pack(pady=10)

attack_label = tk.Label(
    window,
    text="",
    font=("Consolas", 10),
    fg="#fce5e5",
    bg="#ffb7b7",
    justify="left",
    padx=20,
    pady=20,
    relief="groove",
    bd=3
)

attack_label.pack(pady=10)

feedback_label = tk.Label(
    window,
    text="",
    font=("Consolas", 10),
    fg="#fce5e5",
    bg="#ffb7b7",
    justify="left",
    padx=20,
    pady=20,
    relief="groove",
    bd=3
)

feedback_label.pack(pady=10)

window.mainloop()