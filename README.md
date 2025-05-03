# 💼 Job Analyst – ML-Powered Job Recommender

**Job Analyst** is a smart web application built using **Python**, **HTML**, and **CSS**, powered by **Machine Learning (K-Nearest Neighbors)**. It analyzes a user’s skills and recommends relevant job roles by comparing them with existing job data.

## 📸 Demo

![Job Analyst Screenshot](assets/images/demo.png)  
*Replace this with a real screenshot of your project interface.*

## 🛠️ Tech Stack

- 🐍 **Python** – Core logic, data handling
- 📊 **KNN (K-Nearest Neighbors)** – Skill-based job recommendations
- 🌐 **HTML & CSS** – Frontend design and layout
- 🔧 **Libraries** – Pandas, NumPy, Scikit-learn, Flask/Streamlit

## 🎯 How It Works

1. User inputs a list of their skills
2. Skills are vectorized and matched with existing job role data
3. **KNN algorithm** calculates nearest job profiles based on similarity
4. Most relevant job roles are displayed to the user

## 🚀 Features

- ✅ Intelligent job recommendations using ML
- ✅ Interactive and responsive frontend
- ✅ Lightweight and beginner-friendly project
- ✅ Great for portfolios and learning machine learning

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Aditya2S58/job-analyst.git
cd job-analyst

# (Optional) Set up a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install -r requirements.txt

# Run the application (using Streamlit or Flask)
python app.py  # or streamlit run app.py
