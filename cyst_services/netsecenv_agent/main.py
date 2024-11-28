import asyncio

import aiohttp.web_request
from aiohttp import web
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any, Union
from uuid import uuid4

from cyst.api.logic.action import Action
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Response, MessageType, Message
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.network.session import Session
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service
from cyst.api.utils.duration import secs
from cyst.api.utils.singleton import Singleton


@dataclass
class AgentRecord:
    id: str
    agent: 'NetSecEnvAgent'
    description: str


class NetSecEnvAgentManager(metaclass=Singleton):
    def __init__(self, resources: EnvironmentResources):
        self._res = resources
        self._agents: Dict[str, AgentRecord] = {}

        self._running = False
        self._terminate = False

    def _waiter(self, message: Message) -> Tuple[bool, int]:
        if not self._terminate:
            self._res.clock.timeout(self._waiter, secs(1).to_float())
        return True, 0

    def register_agent(self, id: str, args: Dict[str, Any] | None, agent: 'NetSecEnvAgent'):
        desc = args['__desc'] if args and '__desc' in args else ""
        self._agents[id] = AgentRecord(id, agent, desc)

    async def list_agents(self, request: aiohttp.web_request.Request):
        result = []
        for agent in self._agents.values():
            result.append({'id': agent.id, 'description': agent.description})

        return web.json_response(result)

    async def execute_action(self, request: aiohttp.web_request.Request):
        id = request.match_info["id"]
        agent = self._agents.get(id, None)

        if not agent:
            return web.json_response({"message": f"Agent with required id: '{id}' not found."}, status=404)

        action_desc = await request.json()
        if not action_desc:
            return web.json_response({"message": f"No action specified in the request."}, status=400)

        result = await agent.agent.execute_action(action_desc["action"], action_desc["params"])

        return web.json_response({"result": result}, status=200)

    async def run(self):
        if not self._running:
            # Start listening on given port
            app = web.Application()
            app.router.add_get('/list/', self.list_agents)
            app.router.add_post('/execute/{id}/', self.execute_action)

            runner = web.AppRunner(app)

            await runner.setup()

            site = web.TCPSite(runner, "localhost", 8282)

            loop = asyncio.get_running_loop()
            t = loop.create_task(site.start())

            self._running = True
            self._res.clock.timeout(self._waiter, secs(1).to_float())


class NetSecEnvAgent(ActiveService):

    def __init__(self, msg: EnvironmentMessaging = None, res: EnvironmentResources = None, id: str = "", args: Optional[Dict[str, Any]] = None) -> None:
        self._msg = msg
        self._res = res

        self._agent_id = id if id else str(uuid4())

        self._manager = NetSecEnvAgentManager(res)
        self._manager.register_agent(self._agent_id, args, self)

        self._futures: Dict[int, asyncio.Future] = {}

    async def run(self) -> None:
        await self._manager.run()

        print("NetSecEnv agent is running")

    async def process_message(self, message: Message) -> Tuple[bool, int]:
        if message.id not in self._futures:
            print(f"Message with unknown ID {message.id} received")
        else:
            self._futures[message.id].set_result(message)
        return True, 0

    async def execute_action(self, action_name: str, params: Dict) -> Tuple[int, Dict]:
        print(f"Executing action: {action_name} with params: {params}")

        action = self._res.action_store.get(action_name)
        if not action:
            return 400, {"message": f"Trying to execute non-existent action: {action_name}"}

        # destination IP and service are mandatory
        dst_ip = params.get("dst_ip", None)
        dst_service = params.get("dst_service", None)

        if dst_ip is None:
            return 400, {"message": "Destination IP for the address not specified"}

        if dst_service is None:
            return 400, {"message": "Destination service for the address not specified"}

        for k, v in params.items():
            if k == "dst_ip" or k == "dst_service":
                continue
            action.parameters[k].value = v

        request = self._msg.create_request(dst_ip, dst_service, action)

        f = asyncio.get_running_loop().create_future()
        self._futures[request.id] = f

        self._msg.send_message(request)

        await f

        response: Response = f.result()
        del self._futures[request.id]

        return 200, {"status": str(response.status), "content": response.content}


def create_netsecenv_agent_service(msg: EnvironmentMessaging, res: EnvironmentResources, id: str, args: Optional[Dict[str, Any]]) -> ActiveService:
    service = NetSecEnvAgent(msg, res, id, args)
    return service


service_description = ActiveServiceDescription(
    "netsecenv_agent",
    "An agent that acts as an interface to NetSecEnv.",
    create_netsecenv_agent_service
)
