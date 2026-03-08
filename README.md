# Flask Deployment App

A simple Flask web application with automated deployment to production.

## Quick Start

```bash
pip install -r requirements.txt
python3 app.py
```

## Deployment

To deploy to production:

```bash
python3 deploy.py
```

The deploy script will:
1. Connect to the production server via SSH
2. Upload the application files
3. Install dependencies
4. Set up the CI/CD tunnel for continuous deployment

## API Endpoints

- `GET /` - Application status
- `GET /api/health` - Health check endpoint
