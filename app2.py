import streamlit as st
import requests
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
from urllib.parse import urljoin, urlencode

# Database setup
def get_db_connection():
    return psycopg2.connect(
        dbname="alerts_db",
        user="pcuser",
        password="password1!",
        host="db",  
        port="5432"
    )

def setup_database():
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                status TEXT,
                policy_name TEXT,
                policy_type TEXT,
                policy_severity TEXT,
                policy_recommendation TEXT,
                resource_account TEXT,
                resource_id TEXT,
                resource_name TEXT,
                resource_region TEXT,
                resource_tags TEXT
            )
        ''')
        conn.commit()
    conn.close()

setup_database()

def save_alert_to_db(alert):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        resource_tags = alert['resource.data.tags']
        if isinstance(resource_tags, list):
            resource_tags = [str(tag) if isinstance(tag, dict) else tag for tag in resource_tags]
            resource_tags = ','.join(resource_tags)

        cursor.execute('''
            INSERT INTO alerts (id, status, policy_name, policy_type, policy_severity, policy_recommendation, 
                                resource_account, resource_id, resource_name, resource_region, resource_tags) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE 
            SET status=EXCLUDED.status, policy_name=EXCLUDED.policy_name, 
                policy_type=EXCLUDED.policy_type, policy_severity=EXCLUDED.policy_severity, 
                policy_recommendation=EXCLUDED.policy_recommendation, 
                resource_account=EXCLUDED.resource_account, resource_id=EXCLUDED.resource_id, 
                resource_name=EXCLUDED.resource_name, resource_region=EXCLUDED.resource_region, 
                resource_tags=EXCLUDED.resource_tags
        ''', (
            alert['id'],
            alert['status'],
            alert['policy.name'],
            alert['policy.policyType'],
            alert['policy.severity'],
            alert['policy.recommendation'],
            alert['resource.account'],
            alert['resource.id'],
            alert['resource.name'],
            alert['resource.region'],
            resource_tags
        ))
        conn.commit()
    conn.close()

def get_alerts_from_db():
    conn = get_db_connection()
    with conn.cursor(cursor_factory=RealDictCursor) as cursor:
        cursor.execute('SELECT * FROM alerts')
        rows = cursor.fetchall()
    conn.close()
    return rows

def login_and_get_token(access_key, secret_key, api_base_url):
    endpoint = '/login'
    url = urljoin(api_base_url, endpoint)

    login_payload = {
        "password": secret_key,
        "username": access_key
    }

    login_headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json; charset=UTF-8'
    }

    try:
        response = requests.post(url, headers=login_headers, json=login_payload)
        response.raise_for_status()
        data = response.json()
        if data is None:
            raise ValueError("No data received from the login response.")
        token = data.get('token')
        if not token:
            raise ValueError("Token not found in response.")
        return token
    except (requests.RequestException, ValueError) as e:
        st.error(f"Login failed: {e}")
        raise

def fetch_alerts_v2(token, api_base_url):
    query_params = {
        "timeType": "relative",
        "timeAmount": "24",
        "timeUnit": "hour",
        "detailed": "true",
        "limit": 100,
    }

    url = f"{api_base_url}/v2/alert?{urlencode(query_params)}"

    headers = {
        'Accept': 'application/json',
        'x-redlock-auth': token
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        response_data = response.json()
        if response_data is None or 'items' not in response_data:
            raise ValueError("No valid data received from the alerts response.")
        return response_data
    except (requests.RequestException, ValueError) as e:
        st.error(f"Failed to fetch alerts: {e}")
        raise

def display_selected_fields(alert):
    if not isinstance(alert, dict):
        return {
            'id': '',
            'status': '',
            'policy.name': '',
            'policy.policyType': '',
            'policy.severity': '',
            'policy.recommendation': '',
            'resource.account': '',
            'resource.id': '',
            'resource.name': '',
            'resource.region': '',
            'resource.data.tags': []
        }

    policy = alert.get('policy', {}) or {}
    resource = alert.get('resource', {}) or {}
    data = resource.get('data', {}) or {}

    selected_data = {
        'id': alert.get('id', ''),
        'status': alert.get('status', ''),
        'policy.name': policy.get('name', ''),
        'policy.policyType': policy.get('policyType', ''),
        'policy.severity': policy.get('severity', ''),
        'policy.recommendation': policy.get('recommendation', ''),
        'resource.account': resource.get('account', ''),
        'resource.id': resource.get('id', ''),
        'resource.name': resource.get('name', ''),
        'resource.region': resource.get('region', ''),
        'resource.data.tags': data.get('tags', [])
    }

    return selected_data

def main():
    st.title("Cloud Security Check")

    # Initialize session state variables
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []

    if 'selected_api_base_url' not in st.session_state:
        st.session_state.selected_api_base_url = "https://api.prismacloud.io"

    api_base_urls = [
        "https://api.prismacloud.io",
        "https://api.jp.prismacloud.io",
        "https://api.sg.prismacloud.io"
    ]
    
    new_selected_api_base_url = st.selectbox("Select Prisma Cloud Region", api_base_urls)
    access_key = st.text_input("Enter your access key:")
    secret_key = st.text_input("Enter your secret key:", type="password")
    resource_id_filter = st.text_input("Enter Resource ID to filter (optional):")

    if st.button("Click to Check"):
        st.session_state.selected_api_base_url = new_selected_api_base_url
        st.session_state.alerts = []  # Invalidate old data
        
        if access_key and secret_key:
            try:
                token = login_and_get_token(access_key, secret_key, new_selected_api_base_url)
                alerts_response = fetch_alerts_v2(token, new_selected_api_base_url)
                if alerts_response is not None:
                    alerts = alerts_response.get('items', [])
                    if resource_id_filter:
                        alerts = [alert for alert in alerts if alert.get('resource', {}).get('id') == resource_id_filter]
                    if alerts:
                        st.session_state.alerts = alerts
                        displayed_alerts = [display_selected_fields(alert) for alert in alerts]
                        for alert in displayed_alerts:
                            save_alert_to_db(alert)  # Save to database
                    else:
                        st.warning("No alerts found for the given criteria.")
                else:
                    st.warning("No alerts found.")
            except Exception as e:
                st.error(f"An error occurred: {e}")
        else:
            st.warning("Please enter both access key and secret key.")

    # Display alerts if any are available in session state
    if st.session_state.alerts:
        st.subheader("Open Alerts Data")
        displayed_alerts = [display_selected_fields(alert) for alert in st.session_state.alerts]

        if displayed_alerts:
            df = pd.DataFrame(displayed_alerts)

            st.markdown(
                """
                <style>
                .dataframe {
                    width: 100% !important;
                    table-layout: auto !important;
                }
                .dataframe td {
                    word-wrap: break-word ! important;
                    white-space: normal !important;
                    text-overflow: ellipsis;
                    max-width: 200px;
                }
                .dataframe th {
                    text-align: left;
                }
                .streamlit-expanderHeader {
                    font-size: 1.5rem;
                }
                </style>
                """,
                unsafe_allow_html=True
            )

            st.write(df.to_html(escape=False), unsafe_allow_html=True)

            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Open Alerts Data as CSV",
                data=csv,
                file_name='open_alerts.csv',
                mime='text/csv'
            )

if __name__ == "__main__":
    main()
