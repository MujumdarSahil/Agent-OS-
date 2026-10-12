"""
Tests for normalization functions and deduplication key generation.
"""

import pytest

from agentos.jobs.normalize import (
    normalize_company,
    normalize_title,
    normalize_location,
    compute_dedupe_key,
)


@pytest.mark.parametrize(
    "job_a, job_b, description",
    [
        (
            ("Acme Corp.", "Software Engineer", "Remote"),
            ("Acme, Inc.", "Software Engineer", "Remote"),
            "Corp vs Inc legal entity suffixes",
        ),
        (
            ("Infosys Pvt. Ltd.", "Systems Engineer", "Bangalore"),
            ("Infosys Limited", "Systems Engineer", "Bengaluru"),
            "Pvt Ltd vs Limited and Bangalore vs Bengaluru alias",
        ),
        (
            ("Flipkart India Private Limited", "Frontend Engineer", "Bangalore"),
            ("Flipkart India", "Frontend Engineer", "Bengaluru"),
            "Private Limited suffix and Bangalore alias",
        ),
        (
            ("TCS Ltd", "Consultant", "Bombay"),
            ("TCS", "Consultant", "Mumbai"),
            "Ltd suffix and Bombay vs Mumbai alias",
        ),
        (
            ("Wipro", "Data Analyst", "Calcutta"),
            ("Wipro LLC", "Data Analyst", "Kolkata"),
            "LLC suffix and Calcutta vs Kolkata alias",
        ),
        (
            ("Zoho Corp", "Product Developer", "Madras"),
            ("Zoho", "Product Developer", "Chennai"),
            "Corp suffix and Madras vs Chennai alias",
        ),
        (
            ("Razorpay", "Staff Engineer", "remote - india"),
            ("Razorpay Pvt Ltd", "Staff Engineer", "India (Remote)"),
            "Remote - India vs India (Remote)",
        ),
        (
            ("Razorpay", "Staff Engineer", "Remote, India"),
            ("Razorpay", "Staff Engineer", "India - Remote"),
            "Remote, India vs India - Remote",
        ),
        (
            ("Databricks LLC", "Data Engineer", "US (Remote)"),
            ("Databricks", "Data Engineer", "Remote - US"),
            "US (Remote) vs Remote - US",
        ),
        (
            ("Stripe", "Backend Engineer (Go)", "Remote"),
            ("Stripe Inc.", "Backend Engineer - Go", "Remote"),
            "Title punctuation and Inc suffix",
        ),
        (
            ("GOOGLE LLC", "ML Engineer", "NEW YORK"),
            ("Google", "ml engineer", "new york"),
            "Casefold company, title, and location",
        ),
        (
            ("Siemens GmbH", "Security Engineer", "Berlin"),
            ("Siemens PLC", "Security Engineer", "Berlin"),
            "GmbH vs PLC European entity suffixes",
        ),
    ],
)
def test_dedupe_key_same_job_different_formatting(job_a, job_b, description):
    """Pairs representing the same job opportunity must yield identical dedupe keys."""
    key_a = compute_dedupe_key(job_a[0], job_a[1], job_a[2])
    key_b = compute_dedupe_key(job_b[0], job_b[1], job_b[2])
    assert key_a == key_b, f"Failed match on: {description}"


@pytest.mark.parametrize(
    "job_a, job_b, description",
    [
        (
            ("Stripe", "Backend Engineer", "Remote"),
            ("Stripe", "Frontend Engineer", "Remote"),
            "Different titles",
        ),
        (
            ("Google", "Software Engineer", "Remote"),
            ("Meta", "Software Engineer", "Remote"),
            "Different companies",
        ),
        (
            ("Apple", "Software Engineer", "Cupertino"),
            ("Apple", "Software Engineer", "Austin"),
            "Different locations",
        ),
        (
            ("Amazon", "SDE II", "Remote - India"),
            ("Amazon", "SDE II", "Remote - US"),
            "Different remote countries",
        ),
    ],
)
def test_dedupe_key_different_jobs(job_a, job_b, description):
    """Distinct job opportunities must yield distinct dedupe keys."""
    key_a = compute_dedupe_key(job_a[0], job_a[1], job_a[2])
    key_b = compute_dedupe_key(job_b[0], job_b[1], job_b[2])
    assert key_a != key_b, f"Collided on: {description}"


def test_individual_normalization_helpers():
    """Unit check individual normalization helpers."""
    assert normalize_company("Anthropic, PBC.") == "anthropic pbc"
    assert normalize_company("OpenAI LLC") == "openai"
    assert normalize_title("Senior / Lead  Software Engineer!!!") == "senior lead software engineer"
    assert normalize_location("Bangalore, Karnataka") == "bengaluru karnataka"
    assert normalize_location("Remote (India)") == "remote - india"
