import { hasUser, hasExistsUser } from "@database/functions/user";
import { ManageRequestBody } from "@middlewares/manageRequest";
import stringService from "@utils/services/string.services";
import objectService from "@utils/services/object.service";
import userModel from "@database/model/user";

const adminResource = {
    createUser: async ({ data, manageError }: ManageRequestBody) => {
        try {
            let { id, name, space, description, email } = data;
            if (!id || !name) return manageError({ code: "invalid_data" });

            id = stringService.removeSpacesAndLowerCase(id);
            name = stringService.normalizeString(name);

            const userExists = await hasExistsUser({ id }, manageError);
            if (!userExists) return;

            const extra: Partial<any> = {
                lastUpdate: new Date(Date.now()),
                description,
                email
            };

            const createdUser = new userModel({ id, name, ...extra });
            await createdUser.save();

            return createdUser;
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    updateUser: async ({ data, manageError, params }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

            const userExists = await hasUser({ _id: userID }, manageError);
            if (!userExists) return;

            const filteredUser = objectService.filterObject(data, ["id", "order", "role", "createAt", "password", "_id"]);

            if (filteredUser.name){
                filteredUser.name = stringService.normalizeString(filteredUser.name);
            };

            if (filteredUser.description){
                filteredUser.description = stringService.normalizeString(filteredUser.description);
            };

            return await userModel.findByIdAndUpdate(userID, { $set:{ ...filteredUser, lastUpdate: Date.now() } }, { new: true }).select("-password");
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    deleteUser: async ({ manageError, params }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

            const user = await hasUser({ _id: userID }, manageError);
            if (!user) return;
            
            await userModel.findByIdAndDelete(userID);

            return {
                delete: true
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    getUser: async ({ manageError, params }: ManageRequestBody) => {
        try {
            const { userID } =  params;
            if (!userID) return manageError({ code: "invalid_params" });

           return await hasUser({ _id: userID }, manageError);
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    },
    getAllUsers: async ({ manageError, querys }: ManageRequestBody) => {
        try {
            const pageNum = Number(querys.page) || 1;
            const limitNum = Number(querys.limit) || 10;
            const returnType = querys.returnType || "full";

            if (pageNum < 1 || limitNum < 1) return manageError({ code: "invalid_params" });
    
            const skip = (pageNum - 1) * limitNum;
            const [users, total] = await Promise.all([
                userModel.find().sort({ createAt: -1 }).skip(skip).limit(limitNum).select('-password'),
                userModel.countDocuments()
            ]);

            const data = returnType == "minimum" ? users.map(x => ({ _id: x._id, name: x.name, id: x.id })): users;
    
            return {
                data,
                meta: {
                    total,
                    page: pageNum,
                    pages: Math.ceil(total / limitNum),
                    limit: limitNum
                }
            };
        } catch (error) {
            manageError({ code: "internal_error", error });
        }
    }
};

export default adminResource;