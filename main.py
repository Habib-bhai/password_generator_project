import re
import streamlit as st
import random
import string
from google import genai

client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])

def check_password_strength(password):
    score = 0
    
    # Length Check
    if len(password) >= 8:
        score += 1
    else:
        print("❌ Password should be at least 8 characters long.")
    
    # Upper & Lowercase Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        st.write("❌ Include both uppercase and lowercase letters.")
    
    # Digit Check
    if re.search(r"\d", password):
        score += 1
    else:
        st.write("❌ Add at least one number (0-9).")
    
    # Special Character Check
    if re.search(r"[!@#$%^&*]", password):
        score += 1
    else:
        st.write("❌ Include at least one special character (!@#$%^&*).")
    
    # Strength Rating
    if score == 4:
        return "✅ Strong Password!"
    elif score == 3:
        return "⚠️ Moderate Password - Consider adding more security features."
    else:
        return "❌ Weak Password - Improve it using the suggestions above."


def password_generator(length ,includeUpperCase, includeLowerCase, includeDigits, includeSpecialChars):
    characters = ''
    
    if includeUpperCase:
        characters += string.ascii_uppercase
    
    if includeLowerCase:
        characters += string.ascii_lowercase

    if includeDigits:
        characters += string.digits
    
    if includeSpecialChars:
        characters += string.punctuation
    
    return ''.join(random.choice(characters) for _ in range(length))


st.set_page_config(
page_title="Password Strength Checker",
page_icon="🔒",
layout="wide"
)


tab1 , tab2 = st.tabs(["Password Strength Checker", "Password Generator"])

with tab1:
    st.title("Password Strength Checker" )
    st.subheader("LETS SEE IS YOUR PASSWORD STRONG ENOUGH.")
    password = st.text_input("Enter your password", type="password", key="password")

    if st.session_state.password:
        password_checking_result = check_password_strength(st.session_state.password)

        st.write(password_checking_result)


with tab2:
    st.title("Password Generator")
    st.subheader("Generate a strong password using the AI.")

    col_1_checkboxes, col_2_password_result =  st.columns(2)

    with col_1_checkboxes:
        
        
        uppercase_checkbox = st.checkbox("INCLUDE UPPERCASE")
        if uppercase_checkbox not in st.session_state:
            st.session_state.uppercase_checkbox = uppercase_checkbox


        smallcase_checkbox = st.checkbox("INCLUDE SMALL LETTERS")
        if smallcase_checkbox not in st.session_state:
            st.session_state.smallcase_checkbox = smallcase_checkbox

        numbers_checkbox = st.checkbox("INCLUDE NUMERICS")
        if numbers_checkbox not in st.session_state:
            st.session_state.numbers_checkbox = numbers_checkbox

        specialchars_checkbox = st.checkbox("INCLUDE SPECIAL CHARACTERS")
        if specialchars_checkbox not in st.session_state:
            st.session_state.specialchars_checkbox = specialchars_checkbox
        
        
        password_length = st.slider("Select password length", 8, 32, 12)
        if password_length not in st.session_state:
            st.session_state.password_length = password_length
        
        st.button("Generate response", key="generate_response")


        if st.session_state.generate_response:
            password_result = password_generator(password_length,st.session_state.uppercase_checkbox, st.session_state.smallcase_checkbox, st.session_state.numbers_checkbox, st.session_state.specialchars_checkbox)
            st.session_state.password_result = password_result

            with col_2_password_result:
                st.subheader(st.session_state.password_result)
         
        
    st.header("Analyze the Generated password with AI")
    st.button("Start analyzing", key="password_analyze")
    
    if st.session_state.password_analyze:
        response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=f"you are an security expert now, who specializes in password security management. I'll be giving you password that my password generator is generating you have to evaluate that password based on security standards protocols and ethics, you have to check all the requirements of a Very strong password, which has a high entropy. And also you have to provide feedback on, if there is scope of improvement in the password or not. Here is the password{st.session_state.password_result}, and keep in mind you have to be in the limit of 250 words and you can start with sentence like 'OK, GREAT LETS ANALYZE PASSWORD' ",
        )
        
        
        st.write(response.text)
            




