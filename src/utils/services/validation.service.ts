const validationService = {
    validateEmail: (email: string): boolean => {
        const emailRegex = /^[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
        
        if (!emailRegex.test(email)) return false;
        
        const parts = email.split('@');
        if (parts.length !== 2) return false;
        
        const [localPart, domainPart] = parts;
        
        if (localPart.length > 64 || domainPart.length > 255) return false;
        
        if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) return false;
        
        if (domainPart.startsWith('-') || domainPart.endsWith('-')) return false;
        
        const domainLabels = domainPart.split('.');
        if (domainLabels.some(label => label.length > 63)) return false;
        
        return true;
    },

    validateCPF: (cpf: string): boolean => {
        const cleanCPF = cpf.replace(/\D/g, '');
        
        if (cleanCPF.length !== 11) return false;
        
        if (/^(\d)\1{10}$/.test(cleanCPF)) return false;
        
        let sum = 0;
        for (let i = 0; i < 9; i++) {
            sum += parseInt(cleanCPF.charAt(i)) * (10 - i);
        }
        let firstDigit = 11 - (sum % 11);
        if (firstDigit > 9) firstDigit = 0;
        
        if (parseInt(cleanCPF.charAt(9)) !== firstDigit) return false;
        
        sum = 0;
        for (let i = 0; i < 10; i++) {
            sum += parseInt(cleanCPF.charAt(i)) * (11 - i);
        }
        let secondDigit = 11 - (sum % 11);
        if (secondDigit > 9) secondDigit = 0;
        
        if (parseInt(cleanCPF.charAt(10)) !== secondDigit) return false;
        
        return true;
    },

    validateRG: (rg: string): boolean => {
        const cleanRG = rg.replace(/\D/g, '');
        
        if (cleanRG.length < 7 || cleanRG.length > 9) return false;
        
        if (/^(\d)\1+$/.test(cleanRG)) return false;
        
        return true;
    },

    validateCPForRG: (document: string): boolean => {
        const cleanDoc = document.replace(/\D/g, '');
        
        if (cleanDoc.length === 11) {
            return validationService.validateCPF(document);
        } else if (cleanDoc.length >= 7 && cleanDoc.length <= 9) {
            return validationService.validateRG(document);
        }
        
        return false;
    }
};

export default validationService;