import streamlit as st
import pandas as pd
import jwt
import bcrypt
import datetime
from anthropic import Anthropic, HUMAN_PROMPT, AI_PROMPT

# Initialize Anthropic API client
anthropic = Anthropic(api_key=st.secrets["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"])

# JWT secret key
JWT_SECRET = st.secrets["JWT_SECRET"]

# In-memory storage for users and matrices (replace with database in production)
users = {}
matrices = {}

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def create_jwt(user_id):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    return jwt.encode({'user_id': user_id, 'exp': expiration}, JWT_SECRET, algorithm='HS256')

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def register_user(username, password):
    if username not in users:
        users[username] = {
            'password': hash_password(password),
            'id': len(users) + 1
        }
        return True
    return False

def login_user(username, password):
    if username in users and verify_password(users[username]['password'], password):
        return create_jwt(users[username]['id'])
    return None

def save_matrix(user_id, data):
    if user_id not in matrices:
        matrices[user_id] = []
    matrices[user_id].append(data)

def load_matrix(user_id):
    return matrices.get(user_id, [])[-1] if matrices.get(user_id) else None

def generate_ai_response(prompt):
    response = anthropic.completions.create(
        model="claude-2",
        max_tokens_to_sample=300,
        prompt=f"{HUMAN_PROMPT}{prompt}{AI_PROMPT}",
    )
    return response.completion

def main():
    st.set_page_config(page_title="MIPER Generator", layout="wide")
    st.title("MIPER Generator")

    if 'user_id' not in st.session_state:
        st.session_state.user_id = None

    if st.session_state.user_id is None:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            st.header("Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            if st.button("Login"):
                token = login_user(username, password)
                if token:
                    st.session_state.user_id = verify_jwt(token)
                    st.success("Logged in successfully!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")

        with tab2:
            st.header("Register")
            username = st.text_input("Username", key="register_username")
            password = st.text_input("Password", type="password", key="register_password")
            if st.button("Register"):
                if register_user(username, password):
                    st.success("Registered successfully! Please log in.")
                else:
                    st.error("Username already exists")

    else:
        st.sidebar.success("Logged in successfully!")
        if st.sidebar.button("Logout"):
            st.session_state.user_id = None
            st.rerun()

        st.header("Generate MIPER Matrix")

        col1, col2 = st.columns(2)

        with col1:
            process = st.text_input("Proceso/Actividad")
            task = st.text_input("Tarea a realizar")
            position = st.text_input("Puesto de Trabajo")

        with col2:
            risk_factors = st.multiselect("Factores de Riesgo", 
                                          ["Físico", "Químico", "Biológico", "Ergonómico", "Psicosocial", "Mecánico"])
            severity = st.select_slider("Severidad", options=["Baja", "Media", "Alta"])
            probability = st.select_slider("Probabilidad", options=["Baja", "Media", "Alta"])

        if st.button("Generate Matrix"):
            if process and task and position and risk_factors:
                prompt = f"""Generate a risk matrix (MIPER) for the following:
                Process/Activity: {process}
                Task: {task}
                Position: {position}
                Risk Factors: {', '.join(risk_factors)}
                Severity: {severity}
                Probability: {probability}

                Provide the following information:
                1. Task/Situation
                2. Identified Hazard
                3. Associated Damage
                4. Operational Control
                5. Residual Risk (P, C, VRS, Classification)
                6. Control Monitoring Plan (Characteristic to Verify, Limit, Monitoring Method, Responsible for Monitoring, Performance Document, Frequency)
                """
                
                ai_response = generate_ai_response(prompt)
                
                st.subheader("Generated Matrix")
                st.text_area("", ai_response, height=300)
                
                # Save the generated matrix
                save_matrix(st.session_state.user_id, ai_response)
                
                # Export to Excel
                df = pd.DataFrame([ai_response.split('\n')])
                excel_file = df.to_excel(index=False, engine='openpyxl')
                st.download_button(
                    label="Download Excel file",
                    data=excel_file,
                    file_name="miper_matrix.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            else:
                st.warning("Please fill in all required fields")

        # Load and display previous matrix
        previous_matrix = load_matrix(st.session_state.user_id)
        if previous_matrix:
            st.header("Previous Matrix")
            st.text_area("", previous_matrix, height=200)

if __name__ == "__main__":
    main()