from phi.agent import Agent
from phi.model.ollama import Ollama

agent = Agent(
    model=Ollama(id="llama3.1:8b")
)

agent.print_response("Share a 2 sentence horror story.")