**Post-Forensic Visual Storytelling**

A web-based digital forensics prototype designed to make reconstructed cyber incidents easier to understand through interactive visual storytelling.

The project takes structured forensic event data, reconstructs a chronological incident sequence, and presents it through a combination of timeline navigation, simplified visual scenes, supporting evidence, MITRE ATT&CK context, and optional locally generated AI summaries and mitigation guidance.

---------------------------------------------
## Project Motivation

Digital forensic investigations often produce large amounts of technical information such as timestamps, event IDs, authentication records, system activity and network events. While this information is useful to investigators, it can be difficult for non-specialist stakeholders to interpret directly.

This project explores whether a visual communication layer can make reconstructed incidents easier to follow without removing access to the underlying forensic evidence.

The visual storytelling idea was also influenced by simple animated storytelling and stick-figure style representations, with the aim of communicating incident progression using minimal but recognisable actions.

-----------------------------------------------
## Technology Stack

### Frontend
HTML
CSS
JavaScript
Rive Web Runtime
GSAP

### Backend
Python
FastAPI
pandas
NumPy
SQLite

### Security and AI Context
MITRE ATT&CK
Ollama
Qwen2.5 3b-instruct

-----------------------------------------------
## Project Structure

```
project-root/
├── backend/
│   ├── app.py
│   ├── local_summarizer.py
│   └── uploads/
│
├── frontend/
│   ├── main.html
│   └── rive/
│       └── characters.riv
│
├── requirements.txt
└── README.md
```
-------------------------------------------------
## Requirements

Install the following before running the project:
- Python 3.10+
- A modern web browser
- Python dependencies from requirements.txt
- Ollama if the optional local AI features are required

Install the Python dependencies from the project root:
pip install -r requirements.txt

Typical backend dependencies include:
fastapi
uvicorn
pandas
numpy
python-multipart

---------------------------------------------------
### Running the Project

The backend and frontend should be run in separate terminal windows.

1. Start the backend
Move into the backend directory:
cd backend

Run the FastAPI server:
python -m uvicorn app:app --host 0.0.0.0 --port 8000

The backend will be available at:
http://127.0.0.1:8000

FastAPI documentation is available at:
http://127.0.0.1:8000/docs

2. Start the frontend
Open a second terminal and move into the frontend directory:
cd frontend

Run the local frontend server:
python3 -m http.server 5500 --bind 0.0.0.0

Then open:
http://127.0.0.1:5500/main.html

Do not open main.html directly using a file:/// path, as browser restrictions may prevent API requests or animation resources from loading correctly.

Optional Local AI Features

The incident summary and mitigation features run locally through Ollama.

Install the model used during development:
ollama pull qwen2.5:3b-instruct

Check installed models using:
ollama list

If required, start the Ollama service:
ollama serve

The backend communicates with Ollama locally, normally through:
http://127.0.0.1:11434

The AI features are used only after incident reconstruction. They do not replace the underlying evidence or independently determine the forensic meaning of raw records.

-----------------------------------------
### Using the Prototype

Start the backend and frontend servers.
Open the web interface.
Select or import a forensic CSV dataset.
Allow the backend to reconstruct the event sequence.
Navigate through the timeline and visual scenes.
Review event details, evidence and MITRE ATT&CK context where available.
Optionally generate a local AI incident summary or mitigation guidance.
Add investigator notes or export selected report sections.

----------------------------------
### USER STORIES

User stories describe system requirements from the perspective of different users by identifying who will use the system, what they want to achieve, and why the capability is valuable.

1. Digital Forensic Investigator

   As a digital forensic investigator,

   I want to present complex forensic findings through interactive visual stories,

   So that I can improve non-technical stakeholders’ comprehension of cyber incidents and support more informed decision-making.

2. Security Consultant

   As a security consultant,

   I want to review visual reconstructions of previous cyber incidents within a particular organisation,

   So that I can identify recurring attack patterns, explain security weaknesses, and recommend where the organisation should prioritise future security investments.

3. Security Awareness Manager

   As a security awareness manager,

   I want to use visual incident stories based on realistic cyber incidents that have occurred within a particular organisation during employee training,

   So that employees can understand how attacks such as phishing, social engineering, insider threats, and data exfiltration occur, and learn how their actions can influence the progression of a security incident.

4. Cybersecurity Educator

   As a cybersecurity educator,

   I want to use interactive visual stories of historical forensic incidents,

   So that students can better understand incident progression, forensic evidence, and investigative reasoning through realistic case-based learning.

