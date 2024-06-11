type Package = {
    id: string;
    name: string;
    version: string;
    cpe: string[];
    purl: string[];
    vulnerabilities: number;
    maxSeverity: string;
    source: string[];
};

export type { Package };

class Packages {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Package[]>} A promise that resolves to a list of packages
     */
    static async list(): Promise<Package[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/packages?format=list", {
            mode: "cors",
        });
        const data = await response.json();
        return data.map((pkg: Package) => ({
            ...pkg,
            id: pkg.id || `${pkg.name}@${pkg.version}`,
            vulnerabilities: 0,
            maxSeverity: "none",
            source: [],
        }));
    }
}

export default Packages;
