from flask import Flask, render_template, request, jsonify
import sys
import os

# Ensure the current path is included for smooth module imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import all necessary functions from auditor.py
try:
    from auditor import check_strength, check_pwned, calculate_entropy, generate_password, analyze_hash
except ImportError as e:
    # Exit if the critical dependency (auditor.py) is missing
    print(f"Error: Could not import functions from auditor.py. Details: {e}", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)

# ====================================================================
# Helper Function for English Strength Messages
# ====================================================================

def get_strength_messages(score: int, missing_criteria: list[str], entropy: float) -> dict:
    """Determines the general strength message and recommendations in English."""
    
    # Define general strength messages (Score 4/4)
    if score == 4:
        strength_message = "✅ Excellent! This password achieves maximum complexity (4/4)."
        status_color = "success"
    elif score == 3:
        strength_message = "⚠️ Good. The password is acceptable but lacks one element for full complexity."
        status_color = "warning"
    elif score == 2:
        strength_message = "❌ Average. Complexity is weak. Needs additional elements for improvement."
        status_color = "danger"
    else:
        strength_message = "🚨 Very Weak. Easily crackable. Must be changed immediately."
        status_color = "danger"

    # Define recommendations based on failing criteria
    if missing_criteria:
        recommendation = "To enhance password strength, the following are recommended: " + ", ".join(missing_criteria) + "."
    else:
        recommendation = "No complexity improvements suggested (4/4 achieved). Maintain this strength!"

    # Enhance recommendations based on Entropy score
    if entropy < 60:
        recommendation += " Entropy Warning: The randomness score is very low; increase the length to improve it."
    
    # Define English status for Entropy block styling
    if entropy >= 100:
        entropy_status = "Excellent: Highly resistant to brute-force attacks."
        entropy_color = "entropy-excellent"
    elif entropy >= 70:
        entropy_status = "Good: Strong resistance, but still room for improvement."
        entropy_color = "entropy-good"
    else:
        entropy_status = "Poor: Very weak and susceptible to rapid cracking."
        entropy_color = "entropy-poor"

    return {
        'strength_message': strength_message,
        'status_color': status_color,
        'recommendation': recommendation,
        'entropy_status': entropy_status,
        'entropy_color': entropy_color,
    }

# ====================================================================
# Routing and Logic
# ====================================================================

@app.route('/', methods=['GET', 'POST'])
def handle_auditor():
    """Handles both password analysis and hash analysis requests."""
    results = None
    hash_results = None

    if request.method == 'POST':
        
        # --- 1. Handle Hash Analysis ---
        hash_value = request.form.get('hash_input')
        if hash_value and hash_value.strip():
            # Correctly unpack 3 values from auditor.analyze_hash
            try:
                hash_type, recommendations, strength = analyze_hash(hash_value)
            except ValueError as e:
                # Handle error if hash analysis failed to return 3 values (shouldn't happen with the new auditor.py)
                print(f"Hash Analysis Unpack Error: {e}")
                return render_template('index.html', error_message="Hash analysis failed due to an internal error.")


            # Results are set up for display in English
            hash_results = {
                'value': hash_value,
                'type': hash_type,
                'recommendations': recommendations, 
                'strength': strength
            }
        # --- 2. Handle Password Analysis ---
        password = request.form.get('password')
        if password and password.strip():
            # Execute auditing functions
            score, missing_criteria = check_strength(password)
            entropy = calculate_entropy(password)
            breach_status, breach_count = check_pwned(password)
            
            # Prepare English messages and entropy status
            messages = get_strength_messages(score, missing_criteria, entropy)
            
            # Prepare breach details
            if breach_status == "Breached":
                breach_detail = f"🚨 Exposure Confirmed: This password hash was found {breach_count} times in publicly known data breaches. ACTION REQUIRED: Change this password on ALL accounts immediately."
                breach_status = "Breached"
            elif breach_status == "Safe":
                breach_detail = "✅ No Known Exposure: The hash of this password was not found in any publicly disclosed data breaches (Checked against HIBP). Continue to use unique passwords."
                breach_status = "Safe"
            else: # API Error
                breach_detail = "❌ HIBP API Error: Could not verify breach status due to connection failure."
                breach_status = "API Error"
            
            # Compile all results for the template
            results = {
                'password': password,
                'score': score,
                'score_percentage': (score / 4) * 100,
                'entropy': entropy,
                'breach_status': breach_status,
                'breach_detail': breach_detail,
                **messages,
            }
            
    # Final render, sending whichever results are available (or None)
    return render_template('index.html', results=results, hash_results=hash_results)

@app.route('/generate', methods=['POST'])
def generate():
    """Endpoint to generate a secure password."""
    try:
        # Generate a password with a default length of 16 characters
        password = generate_password(16)
        return jsonify({'password': password})
    except Exception as e:
        app.logger.error(f"Error during password generation: {e}")
        return jsonify({'error': 'Failed to generate password'}), 500

if __name__ == '__main__':
    app.run(debug=True)
