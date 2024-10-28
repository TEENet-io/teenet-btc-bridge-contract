import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("bridge", (m) => {
    const pk = m.getParameter("pk");

    const bridge = m.contract("TEENetBtcBridge", [pk]);

    return { bridge };
});