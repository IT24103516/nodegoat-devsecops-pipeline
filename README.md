# NodeGoat DevSecOps Pipeline

## IE3142 - DevOps Security Assignment

### Application Selected
OWASP NodeGoat - an intentionally vulnerable Node.js/Express/MongoDB application, used to demonstrate DevSecOps practices including vulnerability identification, remediation, and CI/CD security automation.

### Tech Stack
- Node.js / Express (Web Application)
- MongoDB (Database)
- Docker / Docker Compose (Containerisation)

### Setup Instructions
1. Install Docker Desktop
2. Clone this repository:
   `git clone https://github.com/IT24103516/nodegoat-devsecops-pipeline.git`
3. Navigate into the folder and run:
   `docker-compose up`
4. Access the application at: http://localhost:4000

### Vulnerabilities Identified & Fixed
1. **Server-Side JS Injection (A1)** - `app/routes/contributions.js` - Replaced insecure `eval()` calls with `parseInt()` to prevent arbitrary code execution and Denial of Service.

### Group Members
- [Herath A.M.O.S] - [IT24103516]
- [Pabasara P.V.I] - [IT24102464]
- [Chinthaka M.D] - [IT24102704]