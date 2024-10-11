import string

def evaluate_password_strength(password):
    # Analyze password length
    length_score = len(password)
    if length_score < 8:
        length_feedback = "Password is too short. Minimum length should be 8 characters."
    elif length_score < 12:
        length_feedback = "Password length is acceptable, but longer is better for increased security."
    else:
        length_feedback = "Password length is good."

    # Analyze password complexity
    complexity_score = 0
    character_sets = [string.digits, string.ascii_lowercase, string.ascii_uppercase, string.punctuation]
    for char_set in character_sets:
        if any(char in char_set for char in password):
            complexity_score += 1

    if complexity_score <= 1:
        complexity_feedback = "Password complexity is poor. Include a mix of uppercase, lowercase, digits, and special characters."
    elif complexity_score == 2:
        complexity_feedback = "Password complexity is fair. Consider adding more character types for better security."
    elif complexity_score == 3:
        complexity_feedback = "Password complexity is good, but adding more special characters would make it stronger."
    else:
        complexity_feedback = "Password complexity is excellent."

    uniqueness_feedback = "Password uniqueness could not be checked."

    # Calculate overall password strength
    strength_score = length_score + complexity_score
    if strength_score < 8:
        strength_feedback = "Password strength is weak."
    elif strength_score < 12:
        strength_feedback = "Password strength is fair."
    elif strength_score < 16:
        strength_feedback = "Password strength is good."
    else:
        strength_feedback = "Password strength is excellent."

    return {
        "length_feedback": length_feedback,
        "complexity_feedback": complexity_feedback,
        "uniqueness_feedback": uniqueness_feedback,
        "strength_feedback": strength_feedback
    }

# Example usage
user_password = input("Enter your password: ")
feedback = evaluate_password_strength(user_password)

print("Length feedback:", feedback["length_feedback"])
print("Complexity feedback:", feedback["complexity_feedback"])
print("Uniqueness feedback:", feedback["uniqueness_feedback"])
print("Overall strength feedback:", feedback["strength_feedback"])