import { Router } from "express";

import controlAccess from "@middlewares/controlAccess";
import usersRouter from "./resources/users.router";
import hasAdmin from "@middlewares/hasAdmin";
import auth from "@middlewares/auth";

const router = Router();

router.get("/ping", (req, res) => {
    res.sendStatus(200);
});

router.get("/validate/control-access", controlAccess, (req, res) => {
    res.sendStatus(200);
});

router.use("/users", [controlAccess],  usersRouter);

export default router;