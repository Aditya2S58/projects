from flask import Flask, render_template, request
import pandas as pd
from sklearn.preprocessing import MultiLabelBinarizer, LabelEncoder
from sklearn.neighbors import NearestNeighbors
import os

app = Flask(__name__)

# Load and preprocess data
df = pd.read_csv(r'C:\Users\aditya\Desktop\programs\python\project\JobCatalyst\ML.csv')

df['Technical Skills'] = df['Technical Skills'].apply(lambda x: x.split(', '))
df['Soft Skills'] = df['Soft Skills'].apply(lambda x: x.split(', '))
df['Certifications'] = df['Certifications'].apply(lambda x: x.split(', ') if pd.notnull(x) else [])
df['Tools/Technologies'] = df['Tools/Technologies'].apply(lambda x: x.split(', ') if pd.notnull(x) else [])

mlb_tech = MultiLabelBinarizer()
mlb_soft = MultiLabelBinarizer()
mlb_certs = MultiLabelBinarizer()
mlb_tools = MultiLabelBinarizer()

tech_skills_df = pd.DataFrame(mlb_tech.fit_transform(df['Technical Skills']), columns=mlb_tech.classes_)
soft_skills_df = pd.DataFrame(mlb_soft.fit_transform(df['Soft Skills']), columns=mlb_soft.classes_)
certs_df = pd.DataFrame(mlb_certs.fit_transform(df['Certifications']), columns=mlb_certs.classes_)
tools_df = pd.DataFrame(mlb_tools.fit_transform(df['Tools/Technologies']), columns=mlb_tools.classes_)

le_edu = LabelEncoder()
df['Educational Qualifications Encoded'] = le_edu.fit_transform(df['Educational Qualifications'])

X = pd.concat([
    tech_skills_df,
    soft_skills_df,
    certs_df,
    tools_df,
    df[['Educational Qualifications Encoded']]
], axis=1)

knn = NearestNeighbors(n_neighbors=3, metric='euclidean')
knn.fit(X)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/recommend', methods=['POST'])
def recommend():
    user_tech = request.form.get('tech_skills').split(', ')
    user_soft = request.form.get('soft_skills').split(', ')
    user_edu = request.form.get('education')
    user_certs = request.form.get('certifications').split(', ') if request.form.get('certifications') else []
    user_tools = request.form.get('tools').split(', ') if request.form.get('tools') else []

    # Encode input
    try:
        user_input = pd.concat([
            pd.DataFrame(mlb_tech.transform([user_tech]), columns=mlb_tech.classes_),
            pd.DataFrame(mlb_soft.transform([user_soft]), columns=mlb_soft.classes_),
            pd.DataFrame(mlb_certs.transform([user_certs]), columns=mlb_certs.classes_),
            pd.DataFrame(mlb_tools.transform([user_tools]), columns=mlb_tools.classes_)
        ], axis=1)
    except Exception:
        return render_template('result.html', jobs=["Invalid input data"], skills={})

    for col in X.columns:
        if col not in user_input.columns:
            user_input[col] = 0

    user_input['Educational Qualifications Encoded'] = le_edu.transform([user_edu])[0] if user_edu in le_edu.classes_ else 0

    distances, indices = knn.kneighbors(user_input)
    recommended_jobs = df.iloc[indices[0]]['Job Title'].values

    # Identify missing skills
    missing_skills = {
        'Technical Skills': set(),
        'Soft Skills': set(),
        'Certifications': set(),
        'Tools/Technologies': set()
    }

    for idx in indices[0]:
        job_row = df.iloc[idx]
        missing_skills['Technical Skills'].update(set(job_row['Technical Skills']) - set(user_tech))
        missing_skills['Soft Skills'].update(set(job_row['Soft Skills']) - set(user_soft))
        missing_skills['Certifications'].update(set(job_row['Certifications']) - set(user_certs))
        missing_skills['Tools/Technologies'].update(set(job_row['Tools/Technologies']) - set(user_tools))

    return render_template('result.html', jobs=recommended_jobs, skills=missing_skills)

if __name__ == '__main__':
    app.run(debug=True)
