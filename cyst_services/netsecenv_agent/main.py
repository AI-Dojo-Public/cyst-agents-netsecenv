import asyncio
import jsonpickle

import aiohttp.web_request
import netaddr
from aiohttp import web
from dataclasses import dataclass
from typing import Tuple, Optional, Dict, Any, Union, List, Set
from uuid import uuid4

from cyst.api.logic.action import Action
from cyst.api.logic.access import Authorization, AuthenticationToken
from cyst.api.environment.environment import EnvironmentMessaging
from cyst.api.environment.message import Request, Response, MessageType, Message
from cyst.api.environment.resources import EnvironmentResources
from cyst.api.network.session import Session
from cyst.api.host.service import ActiveService, ActiveServiceDescription, Service
from cyst.api.utils.counter import Counter
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

        self._actions = {}

        self._sessions = args.get("__sessions", {}) if args else {}
        self._auths = {}

        self._auth_targets: Set[Tuple] = set()
        self._session_targets: Set[Tuple] = set()

    async def run(self) -> None:
        await self._manager.run()

        for action in self._res.action_store.get_prefixed("dojo"):
            self._actions[action.id] = action

        print("NetSecEnv agent is running")

    async def process_message(self, message: Message) -> Tuple[bool, int]:
        if message.id not in self._futures:
            print(f"Message with unknown ID {message.id} received")
        else:
            self._futures[message.id].set_result(message)
        return True, 0

    async def execute_action(self, action_name: str, params: Dict) -> Tuple[int, Dict]:
        print(f"Executing action: {action_name} with params: {params}")

        dst_ip = "127.0.0.1"
        dst_service = ""
        action: Action|None = None
        session: Session|None = None
        auth: Authorization|None = None

        session_name = params.get("session", "")
        if session_name:
            session = self._sessions.get(session_name, None)
            if not session:
                return 400, {"message": f"Attempted to use session with ID: {session_name}, however, no such session present."}

        if action_name.startswith("dojo:"):
            if action_name == "dojo:exfiltrate_data":
                action_name = "dojo:direct:exfiltrate_data"
            action = self._res.action_store.get(action_name)
            if not action:
                return 400,  {"message": f"Attempted to run an unknown action '{action_name}'."}

        # External actions
        # --------------------------------------------------------------------------------------------------------------
        if action_name == "dojo:scan_network":
            network = params.get("to_network", None)
            if not network:
                return 400, {"message": "Missing parameter 'to_network'."}
            action.parameters["to_network"].value = netaddr.IPNetwork(network)
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "dojo:find_services":
            dst_ip = params.get("dst_ip", "")
            if not dst_ip:
                return 400, {"message": "Missing parameter 'dst_ip'."}
            action.parameters["to_network"].value = dst_ip
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "dojo:exploit_server":
            dst_ip = params.get("dst_ip", "")
            if not dst_ip:
                return 400, {"message": "Missing parameter 'dst_ip'."}
            dst_service = params.get("dst_service", "")
            if not dst_service:
                if session and str(session.end[0]) == dst_ip:
                    dst_service = session.end[1]
                else:
                    return 400, {"message": "Missing parameter 'dst_service'."}
            exploit_name = params.get("exploit", "")
            if not exploit_name:
                return 400, {"message": "Missing parameter 'exploit'."}
            exploit = self._res.exploit_store.get_exploit(id=exploit_name)[0]
            if not exploit:
                return 400, {"message": f"Exploit with id '{exploit_name}' not available."}
            action.set_exploit(exploit)
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "dojo:find_data":
            dst_ip = params.get("dst_ip", "")
            if not dst_ip:
                return 400, {"message": "Missing parameter 'dst_ip'."}
            dst_service = params.get("dst_service", "")
            if not dst_service:
                if session and str(session.end[0]) == dst_ip:
                    dst_service = session.end[1]
                else:
                    return 400, {"message": f"Missing parameter 'dst_service'. The provided session does not end in the expected node '{dst_ip}' but in '{session.end[0]}', so its service cannot be used."}
            directory = params.get("directory", "")
            if not directory:
                return 400, {"message": "Missing parameter 'directory'."}
            action.parameters["directory"].value = directory
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "dojo:direct:exfiltrate_data":
            dst_ip = params.get("dst_ip", "")
            if not dst_ip:
                return 400, {"message": "Missing parameter 'dst_ip'."}
            dst_service = params.get("dst_service", "")
            if not dst_service:
                if session and str(session.end[0]) == dst_ip:
                    dst_service = session.end[1]
                else:
                    return 400, {"message": "Missing parameter 'dst_service'."}
            path = params.get("path", "")
            if not path:
                return 400, {"message": "Missing parameter 'path'."}
            action.parameters["path"].value = path
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "dojo:block_ip":
            return 400,  {"message": "Blocking of IPs is not yet implemented."}
        # --------------------------------------------------------------------------------------------------------------
        # Internal actions
        elif action_name == "agent:list_sessions":
            result = dict()
            result["sessions"] = []
            for session in self._sessions.values():
                result["sessions"].append({
                    "session id": session.id,
                    "session start": f"{str(session.start[0])} [{session.start[1]}]",
                    "session end": f"{str(session.end[0])} [{session.end[1]}]"
                })
            return 200, result
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "agent:list_exploits":
            result = dict()
            result["exploits"] = []
            for exploit in self._res.exploit_store.get_exploit():
                vulnerable_services = []
                for service in exploit.services.values():
                    vulnerable_services.append(f"{service.id} ({str(service.min_version)} - {str(service.max_version)})")
                result["exploits"].append(
                    {
                        "exploit id": exploit.id,
                        "exploit category": exploit.category.name,
                        "exploit locality": exploit.locality.name,
                        "vulnerable services": vulnerable_services
                    }
                )
            return 200, result
        # --------------------------------------------------------------------------------------------------------------
        elif action_name == "agent:list_auths":
            result = dict()
            result["auths"] = []
            for a in self._auths.values():
                result["auths"].append({
                    "auth id": a[0],
                    "dst ip": a[1],
                    "dst service": a[2]
                })
            return 200, result
        else:
            return 400, {"message": f"Trying to execute non-existent action: {action_name}"}

        auth_name = params.get("auth", "")
        if auth_name:
            auth_entry = self._auths.get(auth_name, None)
            if not auth_entry:
                return 400, {"message": f"Attempted to use auth with ID: {auth_name}, however, no such auth present."}
            auth=auth_entry[3]

        request = self._msg.create_request(dst_ip, dst_service, action, session=session, auth=auth)

        f = asyncio.get_running_loop().create_future()
        self._futures[request.id] = f

        self._msg.send_message(request)

        await f

        response: Response = f.result()
        del self._futures[request.id]

        # Check if there is a new authorization in the response
        new_auth_id = ""
        if response.auth:
            if not (dst_ip, dst_service) in self._auth_targets:
                auth_id = "authorization_" + str(Counter().get("netsecenv_authorization"))
                new_auth_id = auth_id
                auth_entry = [auth_id, dst_ip, dst_service, response.auth]
                self._auths[auth_id] = auth_entry
                self._auth_targets.add((dst_ip, dst_service))

        # Check if there is a new session in the response
        # We are ignoring multiple sessions that are opened to the same destination (even though they will be displayed
        # in the session list.
        new_session_id = ""
        if response.session:
            if not response.session.end in self._session_targets:
                new_session_id = response.session.id
                self._session_targets.add(response.session.end)

        result = {"id": request.id, "status": str(response.status), "new_auth_id": new_auth_id,
                  "new_session_id": new_session_id, "content": str(response.content), "message": str(response)}

        return 200, result


def create_netsecenv_agent_service(msg: EnvironmentMessaging, res: EnvironmentResources, id: str, args: Optional[Dict[str, Any]]) -> ActiveService:
    service = NetSecEnvAgent(msg, res, id, args)
    return service


service_description = ActiveServiceDescription(
    "netsecenv_agent",
    "An agent that acts as an interface to NetSecEnv.",
    create_netsecenv_agent_service
)
