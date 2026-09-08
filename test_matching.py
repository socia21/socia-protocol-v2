"""
Standalone harness for exercising compute_match_score / compute_match_breakdown
against realistic listing combinations, without needing the full FastAPI app,
HTTP layer, or a real Postgres DB. Uses a throwaway sqlite file.

Run with: DATABASE_URL="sqlite:///./test_scoring.db" python3 test_matching.py
"""
import os
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_scoring.db")
os.environ.setdefault("JWT_SECRET", "testsecret")
os.environ.setdefault("ADMIN_SECRET", "testadmin")

# Fresh DB each run so test data doesn't pile up across iterations
if os.path.exists("test_scoring.db"):
    os.remove("test_scoring.db")

import main
from sqlmodel import Session, select

main.create_db_and_tables()

def mk(session, **kw):
    defaults = dict(
        contact="x@example.com", name="X", role="influencer", industry="", rates="", stats="", bio="",
        pre_conditions_str="", budget_min=0, budget_max=0, audience_size=0, engagement_rate=0,
        niche_tags="", is_anonymous=False, location="", platforms="", content_languages="",
        interests="", hide_location_publicly=False, verified=True,
    )
    defaults.update(kw)
    listing = main.MarketplaceListing(**defaults)
    session.add(listing)
    session.commit()
    session.refresh(listing)
    return listing

with Session(main.engine) as session:
    print("=" * 70)
    print("TEST 1: Sponsor with NO stated minimums vs. a well-matched creator")
    print("=" * 70)
    sponsor = mk(session, contact="sponsor1@brand.com", name="Acme Fitness Co", role="sponsor",
                 industry="Fitness & Wellness", budget_min=1000, budget_max=5000,
                 audience_size=0, engagement_rate=0,  # sponsor left "requirements" blank
                 niche_tags="fitness,wellness", location="Mumbai, India",
                 platforms="Instagram,YouTube", content_languages="English")
    creator = mk(session, contact="creator1@example.com", name="Fit With Dee", role="influencer",
                 industry="Fitness & Wellness", budget_min=2000, budget_max=4000,
                 audience_size=80000, engagement_rate=4.2,
                 niche_tags="fitness,wellness,yoga", location="Mumbai, Maharashtra",
                 platforms="Instagram,YouTube,TikTok", content_languages="English,Hindi", verified=True)
    score = main.compute_match_score(sponsor, creator)
    breakdown = main.compute_match_breakdown(sponsor, creator)
    print(f"Score: {score}")
    print(f"Reasons: {breakdown['reasons']}")
    for k, v in breakdown["factors"].items():
        print(f"  {k:22s} applicable={v['applicable']!s:5} earned={v['earned']:.2f}/{v['weight']}")

    print()
    print("=" * 70)
    print("TEST 2: Same pair, but location now string-mismatched ('Mumbai' vs 'Mumbai, Maharashtra')")
    print("        and sponsor requires local presence -> should still match (normalized)")
    print("=" * 70)
    sponsor.requires_local_presence = True
    sponsor.location = "Mumbai"
    session.add(sponsor); session.commit(); session.refresh(sponsor)
    score2 = main.compute_match_score(sponsor, creator)
    breakdown2 = main.compute_match_breakdown(sponsor, creator)
    print(f"Score: {score2}  (location factor: {breakdown2['factors']['location']})")

    print()
    print("=" * 70)
    print("TEST 3: Sponsor sets a REAL minimum audience/engagement bar the creator fails")
    print("=" * 70)
    sponsor.audience_size = 500000       # wants a much bigger creator than Dee
    sponsor.engagement_rate = 6.0        # wants higher engagement than Dee has
    session.add(sponsor); session.commit(); session.refresh(sponsor)
    score3 = main.compute_match_score(sponsor, creator)
    breakdown3 = main.compute_match_breakdown(sponsor, creator)
    print(f"Score: {score3} (was {score2} before minimums added)")
    print(f"  audience_engagement factor: {breakdown3['factors']['audience_engagement']}")

    print()
    print("=" * 70)
    print("TEST 4: Brand-safety conflict -- sponsor excludes 'gambling', creator tagged 'gambling'")
    print("=" * 70)
    sponsor.excluded_niches = "gambling,alcohol"
    creator.niche_tags = "fitness,wellness,gambling"
    session.add(sponsor); session.add(creator); session.commit()
    session.refresh(sponsor); session.refresh(creator)
    score4 = main.compute_match_score(sponsor, creator)
    breakdown4 = main.compute_match_breakdown(sponsor, creator)
    print(f"Score: {score4}")
    print(f"  brand_safety factor: {breakdown4['factors']['brand_safety']}")

    print()
    print("=" * 70)
    print("TEST 5: Blank-data loophole check -- two listings with almost NOTHING filled in")
    print("        should NOT score artificially high just because fields are empty")
    print("=" * 70)
    sponsor_blank = mk(session, contact="blank_sponsor@brand.com", role="sponsor", name="Blank Co")
    creator_blank = mk(session, contact="blank_creator@example.com", role="influencer", name="Blank Creator")
    score5 = main.compute_match_score(sponsor_blank, creator_blank)
    breakdown5 = main.compute_match_breakdown(sponsor_blank, creator_blank)
    print(f"Score: {score5}  (should be modest/neutral, not inflated)")
    for k, v in breakdown5["factors"].items():
        print(f"  {k:22s} applicable={v['applicable']!s:5} earned={v['earned']:.2f}/{v['weight']}")

    print()
    print("=" * 70)
    print("TEST 6: Reliability signal -- creator with a clean track record vs. one with disputes")
    print("=" * 70)
    good_signal = {"completed": 8, "disputed": 0, "refunded": 0, "pitches_received": 10, "pitches_answered": 10}
    bad_signal = {"completed": 2, "disputed": 4, "refunded": 1, "pitches_received": 10, "pitches_answered": 3}
    score_good = main.compute_match_score(sponsor_blank, creator_blank, reliability_signal=good_signal)
    score_bad = main.compute_match_score(sponsor_blank, creator_blank, reliability_signal=bad_signal)
    print(f"Clean track record score: {score_good}")
    print(f"Poor track record score:  {score_bad}")
    assert score_good > score_bad, "Reliability signal should meaningfully move the score"

    print()
    print("=" * 70)
    print("TEST 7: viewer_listing is None -> must return None (unchanged contract)")
    print("=" * 70)
    print(main.compute_match_score(None, creator))
    assert main.compute_match_score(None, creator) is None

    print()
    print("=" * 70)
    print("TEST 8: Same-role pair (sponsor vs sponsor) must not crash")
    print("=" * 70)
    other_sponsor = mk(session, contact="sponsor2@brand.com", role="sponsor", name="Other Brand",
                        niche_tags="tech", budget_min=100, budget_max=200)
    s8 = main.compute_match_score(sponsor, other_sponsor)
    print(f"Score: {s8} (no crash)")

print()
print("ALL TESTS COMPLETED WITHOUT ERROR")
