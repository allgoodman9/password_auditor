import argparse
import statistics
from typing import List, Dict, Any

MIN_DEFAULT_LENGTH = 8


def analyze_password(password: str, min_length: int = MIN_DEFAULT_LENGTH) -> Dict[str, Any]:
    """Return detailed analysis of a single password."""
    raw = password.rstrip("\n\r")
    length = len(raw)

    has_lower = any(c.islower() for c in raw)
    has_upper = any(c.isupper() for c in raw)
    has_digit = any(c.isdigit() for c in raw)
    has_symbol = any(not c.isalnum() for c in raw)

    score = 0
    warnings = []


    if length >= min_length:
        score += 2
    if length >= min_length + 4:
        score += 2
    if length < min_length:
        warnings.append(f"Password is shorter than recommended minimum ({min_length}).")


    categories = [has_lower, has_upper, has_digit, has_symbol]
    score += sum(1 for flag in categories if flag)

    if sum(categories) <= 1:
        warnings.append("Use a mix of lowercase, uppercase, digits and symbols.")


    if length > 0 and len(set(raw)) == 1:
        warnings.append("Password is made of a single repeated character.")
        score -= 2

    if raw.lower() in {"password", "qwerty", "123456", "letmein"}:
        warnings.append("Password is a very common weak password.")
        score -= 3


    if score < 0:
        score = 0

    if score <= 3:
        strength = "WEAK"
    elif score <= 6:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return {
        "password": raw,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "score": score,
        "strength": strength,
        "warnings": warnings,
    }


def analyze_file(path: str, min_length: int) -> Dict[str, Any]:
    """Analyze all passwords in the given file."""
    results: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if not line:

                    continue
                results.append(analyze_password(line, min_length=min_length))
    except FileNotFoundError:
        raise SystemExit(f"Error: file '{path}' not found.")
    except OSError as e:
        raise SystemExit(f"Error reading file '{path}': {e}")

    if not results:
        raise SystemExit("Error: no passwords found in file (file is empty or only blank lines).")

    lengths = [r["length"] for r in results]
    scores = [r["score"] for r in results]

    summary = {
        "total_passwords": len(results),
        "min_length": min(lengths),
        "max_length": max(lengths),
        "avg_length": statistics.mean(lengths),
        "avg_score": statistics.mean(scores),
        "count_by_strength": {
            "WEAK": sum(1 for r in results if r["strength"] == "WEAK"),
            "MEDIUM": sum(1 for r in results if r["strength"] == "MEDIUM"),
            "STRONG": sum(1 for r in results if r["strength"] == "STRONG"),
        },
    }

    return {"results": results, "summary": summary}


def print_report(analysis: Dict[str, Any], top_n: int = 5) -> None:
    """Print human-readable report to stdout."""
    results = analysis["results"]
    summary = analysis["summary"]

    print("=== Password audit report ===\n")
    print(f"Total passwords: {summary['total_passwords']}")
    print(
        f"Length: min={summary['min_length']}, "
        f"max={summary['max_length']}, avg={summary['avg_length']:.2f}"
    )
    print(f"Average score: {summary['avg_score']:.2f}")
    print("Strength distribution:")
    for level, count in summary["count_by_strength"].items():
        percent = (count / summary["total_passwords"]) * 100
        print(f"  {level:6}: {count:3} ({percent:5.1f}%)")

    print("\nTop weakest passwords:")
    weakest = sorted(results, key=lambda r: (r["score"], r["length"]))[:top_n]
    for r in weakest:
        display = r["password"] if len(r["password"]) <= 20 else r["password"][:17] + "..."
        print(
            f"  - '{display}' | score={r['score']} | "
            f"strength={r['strength']} | length={r['length']}"
        )
        for w in r["warnings"]:
            print(f"      ! {w}")

    print("\nDetailed results (first 10 passwords):")
    for r in results[:10]:
        display = r["password"] if len(r["password"]) <= 20 else r["password"][:17] + "..."
        flags = []
        if r["has_lower"]:
            flags.append("lower")
        if r["has_upper"]:
            flags.append("upper")
        if r["has_digit"]:
            flags.append("digit")
        if r["has_symbol"]:
            flags.append("symbol")
        flags_str = ",".join(flags) if flags else "none"
        print(
            f"  '{display}' -> {r['strength']} "
            f"(score={r['score']}, length={r['length']}, chars={flags_str})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple password strength auditor. "
        "Reads passwords from a file and prints a report."
    )
    parser.add_argument(
        "file",
        help="Path to a text file with one password per line.",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=MIN_DEFAULT_LENGTH,
        help=f"Recommended minimum password length (default: {MIN_DEFAULT_LENGTH}).",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="How many weakest passwords to show in detail (default: 5).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    analysis = analyze_file(args.file, min_length=args.min_length)
    print_report(analysis, top_n=args.top)


if __name__ == "__main__":
    main()
