import type { Package } from "../handlers/packages";
import type { Vulnerability } from "../handlers/vulnerabilities";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale } from 'chart.js';
import { Pie, Line, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale);

type Props = {
    packages: Package[];
    vulnerabilities: Vulnerability[];
};


const pieOptions = {
    maintainAspectRatio: true,
    plugins: {
        legend: {
            position: 'bottom' as const,
            labels: {
                color: '#ccc'
            }
        }
    }
}

const LineOptions = {
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: false
        }
    },
    elements: {
        point: {
            radius: 6
        },
        line: {
            borderWidth: 3,
            borderColor: '#aaa'
        }
    },
    scales: {
        y: {
            beginAtZero: true
        }
    }
}

const BarOptions = {
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: false
        }
    }
};

function Metrics ({ vulnerabilities }: Props) {

    const vulnBySeverity = {
        labels: ['Unknown', 'Low', 'Medium', 'High', 'Critical'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: vulnerabilities.reduce((acc, vuln) => {
                const severity = vuln.severity.severity.toUpperCase();
                const index = Math.max(SEVERITY_ORDER.indexOf(severity) - 1, 0)
                acc[index]++;
                return acc;
            }, [0, 0, 0, 0, 0]),
            backgroundColor: [
                'rgba(180, 180, 180)',
                'rgba(0, 150, 150)',
                '#F8DE22',
                '#F94C10',
                '#FC2947',
            ],
            hoverOffset: 4
        }]
    };

    const vulnByStatus = {
        labels: ['Pending analysis', 'Fixed', 'Not Affected', 'Active'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: vulnerabilities.reduce((acc, vuln) => {
                const status = vuln.simplified_status;
                const index = status == 'pending analysis' ? 0 : status == 'fixed' ? 1 : status == 'not affected' ? 2 : 3;
                acc[index]++;
                return acc;
            }, [0, 0, 0, 0]),
            backgroundColor: [
                'rgba(180, 180, 180)',
                '#40A578',
                'rgba(0, 150, 150)',
                '#F94C10',
            ],
            hoverOffset: 4
        }]
    }

    const vulnEvolutionTime = {
        labels: ['feb 24', 'march 24', 'april 24', 'may 24', 'june 24'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: [512, 483, 430, 380, 440],
            backgroundColor: [
                '#C63D2F',
                '#E25E3E',
                '#FF9B50',
                '#FFBB5C',
                '#FFDB5A',
            ],
            hoverOffset: 4
        }]
    }

    const vulnBySource = {
        labels: ['Unknown', 'Grype', 'Yocto', 'OSV'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: vulnerabilities.reduce((acc, vuln) => {
                const source = vuln.found_by;
                const index = source == 'grype' ? 1 : source == 'yocto' ? 2 : source == 'osv' ? 3 : 0;
                acc[index]++;
                return acc;
            }, [0, 0, 0, 0]),
            backgroundColor: [
                'rgba(180, 180, 180)',
                'rgba(0, 150, 150)',
                '#F8DE22',
                '#F94C10',
                '#FC2947',
            ],
            hoverOffset: 4
        }]
    }

    return (
        <div className="w-full flex flex-wrap">

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Severity</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Pie data={vulnBySeverity} options={pieOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Status</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Pie data={vulnByStatus} options={pieOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Active vulnerabilities <i>[fake data]</i></div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Line data={vulnEvolutionTime} options={LineOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Source</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Bar data={vulnBySource} options={BarOptions} />
                </div>
            </div>

        </div>
    );
}

export default Metrics;
