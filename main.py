# =============================================================================
# aviation_ci_app | Local FastAPI service entry point
#
# Responsibility: Preserve existing PyCharm startup behavior while launching the aviation_ci_app application on
#   loopback.
# Design boundary: API routing and all intelligence processing live in imported backend modules.
# =============================================================================


"""aviation_ci_app FastAPI entrypoint.

Keep this file named main.py for existing PyCharm run configurations.
"""

# Import the shared FastAPI application without duplicating route definitions.
from ews_api import app
import os
# Initialize LiteLLM local-model cost behavior before launching the server.
os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
from ews_state import logger
import uvicorn


# Expose the development service on loopback only; no public network interface is opened.
if __name__ == "__main__":
    logger.info("Starting local Aerospace EWS server...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
