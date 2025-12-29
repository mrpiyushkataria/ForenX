def calculate_risk_score(
    hit_count: int,
    data_volume: int,
    unique_ips: int,
    requests_per_minute: float = 0.0
) -> int:
    """
    Calculate risk score (0-100) based on multiple factors.
    Implements Risk Scoring Engine from requirements.
    """
    score = 0
    
    # Factor 1: Request volume
    if hit_count > 10000:
        score += 40
    elif hit_count > 1000:
        score += 25
    elif hit_count > 100:
        score += 15
    elif hit_count > 10:
        score += 5
    
    # Factor 2: Data volume (potential dump)
    if data_volume > 100000000:  # 100MB
        score += 35
    elif data_volume > 10000000:  # 10MB
        score += 25
    elif data_volume > 1000000:   # 1MB
        score += 15
    elif data_volume > 100000:    # 100KB
        score += 5
    
    # Factor 3: Unique IPs (distributed attack)
    if unique_ips > 100:
        score += 25
    elif unique_ips > 10:
        score += 15
    elif unique_ips > 3:
        score += 5
    
    # Factor 4: Request rate (automation)
    if requests_per_minute > 100:
        score += 30
    elif requests_per_minute > 50:
        score += 20
    elif requests_per_minute > 20:
        score += 10
    
    # Cap at 100
    return min(100, score)
