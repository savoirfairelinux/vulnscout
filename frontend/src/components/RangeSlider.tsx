import { useState, useMemo, useCallback } from "react";

type Props = {
  min: number;
  max: number;
  step?: number;
  initialMin?: number;
  initialMax?: number;
  onChange?: (range: { min: number; max: number }) => void;
};

export default function RangeSlider({
  min,
  max,
  step = 1,
  initialMin = min,
  initialMax = max,
  onChange,
}: Props) {
  const [minVal, setMinVal] = useState(initialMin);
  const [maxVal, setMaxVal] = useState(initialMax);

  const percent = useCallback((value: number) => ((value - min) / (max - min)) * 100, [min, max]);
  
  const minPercent = useMemo(() => percent(minVal), [minVal, percent]);
  const maxPercent = useMemo(() => percent(maxVal), [maxVal, percent]);

  const updateMin = (v: number) => {
    const next = Math.min(v, maxVal); // clamp to maxVal
    setMinVal(next);
    onChange?.({ min: next, max: maxVal });
  };

  const updateMax = (v: number) => {
    const next = Math.max(v, minVal); // clamp to minVal
    setMaxVal(next);
    onChange?.({ min: minVal, max: next });
  };

  return (
    <div className="w-full">
      <div className="flex justify-between text-sm text-white mb-2">
        <span>Min: {minVal}</span>
        <span>Max: {maxVal}</span>
      </div>

      <div className="relative h-8">
        {/* track */}
        <div className="absolute left-0 right-0 top-1/2 -translate-y-1/2 h-2 rounded bg-slate-800" />
        {/* selected range highlight */}
        <div
          className="absolute top-1/2 -translate-y-1/2 h-2 rounded bg-sky-500"
          style={{
            left: `${minPercent}%`,
            width: `${maxPercent - minPercent}%`,
          }}
        />
        {/* min thumb */}
        <input
          type="range"
          min={min}
          max={max}
          step={step}
          value={minVal}
          onChange={(e) => updateMin(Number(e.target.value))}
          className="pointer-events-none absolute inset-0 appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-white [&::-moz-range-thumb]:pointer-events-auto [&::-moz-range-thumb]:h-4 [&::-moz-range-thumb]:w-4 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-white"
          style={{ zIndex: minVal > max - (max - min) * 0.05 ? 5 : 3 }}
        />
        {/* max thumb */}
        <input
          type="range"
          min={min}
          max={max}
          step={step}
          value={maxVal}
          onChange={(e) => updateMax(Number(e.target.value))}
          className="pointer-events-none absolute inset-0 appearance-none bg-transparent [&::-webkit-slider-thumb]:pointer-events-auto [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-white [&::-moz-range-thumb]:pointer-events-auto [&::-moz-range-thumb]:h-4 [&::-moz-range-thumb]:w-4 [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-white"
          style={{ zIndex: 4 }}
        />
      </div>
    </div>
  );
}