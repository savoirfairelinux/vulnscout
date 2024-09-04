import type { CVSS } from "../handlers/vulnerabilities";

type Props = {
    data: CVSS;
};

function CvssGauge ({ data }: Props) {
    //percent to deg => Math.round(((value / 100) * 180 - 45) * 10) / 10
    // src: https://gist.github.com/gquittet/77dd931ebfa7b8a73f2711faee0a7292

    if (typeof data.base_score !== 'number' || data.base_score < 0.0 || data.base_score > 10.0)
        return <></>;

    // score is in the range 0-10, so we multiply by 18 to get the angle
    const score_angle = Number(data.base_score) * 18 - 45;
    let score_color = 'bg-green-500';
    if (data.base_score >= 4.0)
        score_color = 'bg-orange-500';
    if (data.base_score >= 7.0)
        score_color = 'bg-red-500';
    if (data.base_score >= 9.0)
        score_color = 'bg-red-900';

    return (
    <div className="bg-gray-800 w-[216px] aspect-[2] overflow-hidden">
        <div className="relative flex items-center justify-center bg-gray-800">
            {/* Outer ring with ranges (rotate angles modifiable to get custom range) */}
            <div className="absolute top-0 aspect-square w-full rounded-full rotate-[calc(0deg-45deg)] bg-gradient-to-tr from-transparent from-50% to-green-600 to-50% transition-transform duration-500"></div>
            <div className="absolute top-0 aspect-square w-full rounded-full rotate-[calc(72deg-45deg)] bg-gradient-to-tr from-transparent from-50% to-orange-400 to-50% transition-transform duration-500"></div>
            <div className="absolute top-0 aspect-square w-full rounded-full rotate-[calc(126deg-45deg)] bg-gradient-to-tr from-transparent from-50% to-red-500 to-50% transition-transform duration-500"></div>
            <div className="absolute top-0 aspect-square w-full rounded-full rotate-[calc(162deg-45deg)] bg-gradient-to-tr from-transparent from-50% to-red-800 to-50% transition-transform duration-500"></div>

            <div className="relative flex w-full p-4">
                {/* Optional black seperation if the gauge has the same colour as the outer ring */}
                <div className="absolute flex aspect-square justify-center rounded-full bg-black w-[calc(100%-2rem)]"></div>

                <div className="relative flex w-full p-1">
                    {/* Actual gauge, change angle again for a dynamic value */}
                    <div className={`absolute flex aspect-square w-[calc(100%-0.5rem)] justify-center rounded-full ${score_color}`}></div>

                    <div className="relative flex w-full">
                        <div style={{transform: `rotate(${score_angle}deg)`}} className="absolute aspect-square w-full rounded-full bg-gradient-to-tr from-transparent from-50% to-gray-800 to-50% transition-transform duration-500"></div>

                        <div className="relative flex w-full p-2">
                            <div className="absolute flex aspect-square w-[calc(100%-1rem)] justify-center rounded-full bg-gray-800 "></div>
                        </div>
                    </div>
                </div>
            </div>
            <div className="absolute bottom-2 w-full truncate text-center translate-y-6 text-3xl">{data.base_score}</div>
            <div className="absolute bottom-2 w-full truncate text-center translate-y-12 text-sm">{data.author}</div>
        </div>
    </div>
    );
}

export default CvssGauge;
