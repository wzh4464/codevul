from scripts.cwe_stats import main as generate_cwe_stats
from scripts.category_summary import generate_category_summary


def main():
    print("Generating CWE statistics...")
    generate_cwe_stats()
    print("Done. Output saved to cwe_counts.json.")
    print("Aggregating per-category summaries...")
    generate_category_summary()
    print("Category summaries written.")


if __name__ == "__main__":
    main()
