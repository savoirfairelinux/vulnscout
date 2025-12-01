import { useState, useEffect } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion } from '@fortawesome/free-regular-svg-icons';
import Iso8601Duration from '../handlers/iso8601duration';
import MessageBanner from './MessageBanner';

type PostTimeEstimate = {
    optimistic: Iso8601Duration,
    likely: Iso8601Duration,
    pessimistic: Iso8601Duration
}

type ActualEstimate = {
    optimistic?: string,
    likely?: string,
    pessimistic?: string
}

type Props = {
    actualEstimate: ActualEstimate;
    onSaveTimeEstimation: (data: PostTimeEstimate) => void;
    clearFields?: boolean;
    progressBar?: number;
    onFieldsChange?: (hasChanges: boolean) => void;
    triggerBanner?: (message: string, type: "error" | "success") => void;
    hideInputs?: boolean;
}

function TimeEstimateEditor ({onSaveTimeEstimation, clearFields: shouldClearFields, progressBar, actualEstimate, onFieldsChange, triggerBanner, hideInputs}: Readonly<Props>) {
    const [estimateHelp, setEstimateHelp] = useState(false);
    const [newOptimistic, setNewOptimistic] = useState("");
    const [newLikely, setNewLikely] = useState("");
    const [newPessimistic, setNewPessimistic] = useState("");
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);

    const internalTriggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const clearFields = () => {
        setNewOptimistic("");
        setNewLikely("");
        setNewPessimistic("");
    };

    useEffect(() => {
        if (shouldClearFields) {
            clearFields();
        }
    }, [shouldClearFields]);

    // Check if fields have changes
    useEffect(() => {
        const hasChanges = (
            newOptimistic !== "" ||
            newLikely !== "" ||
            newPessimistic !== ""
        );
        onFieldsChange?.(hasChanges);
    }, [newOptimistic, newLikely, newPessimistic, onFieldsChange]);

    const saveEstimation = async () => {
        if (!newOptimistic || !newLikely || !newPessimistic) {
            const errorMessage = "All time estimate fields must be filled.";
            if (triggerBanner) {
                triggerBanner(errorMessage, "error");
            } else {
                internalTriggerBanner(errorMessage, "error");
            }
            return;
        }

        let content: PostTimeEstimate|undefined = undefined;
        try {
            content = {
                optimistic: new Iso8601Duration(newOptimistic),
                likely: new Iso8601Duration(newLikely),
                pessimistic: new Iso8601Duration(newPessimistic)
            }

            if(content.optimistic.total_seconds <= 0)
                throw new Error('Invalid optimistic duration, must be strictly positive');
            if(content.likely.total_seconds <= 0)
                throw new Error('Invalid likely duration, must be strictly positive');
            if(content.pessimistic.total_seconds <= 0)
                throw new Error('Invalid pessimistic duration, must be strictly positive');
            if(content.optimistic.total_seconds > content.likely.total_seconds)
                throw new Error('Optimistic duration must be lower than likely duration');
            if(content.likely.total_seconds > content.pessimistic.total_seconds)
                throw new Error('Likely duration must be lower than pessimistic duration');
        } catch (e) {
            if (triggerBanner) {
                triggerBanner(`Failed to parse estimation: ${String(e)}`, "error");
            } else {
                internalTriggerBanner(`Failed to parse estimation: ${String(e)}`, "error");
            }
            return;
        }

        if (content != undefined) {
            onSaveTimeEstimation(content);
        }
    };

    return (<>
        {!triggerBanner && bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}

        <div className="flex items-center gap-2">
            <h3 className="font-bold">Estimated efforts to fix</h3><button type='button' className='hover:text-blue-400' onClick={() => setEstimateHelp(!estimateHelp)}>
                <FontAwesomeIcon icon={faCircleQuestion} size='lg' className='pr-2' />
            </button>
        </div>

        <div className="flex flex-row space-x-4 max-w-[900px]">
            <div className="flex-1">
                <h4 className="font-bold">Optimistic</h4>
                <p>{actualEstimate.optimistic ?? "N/A"}</p>
                {!hideInputs && (
                    <input
                        value={newOptimistic}
                        onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewOptimistic(event.target.value)}
                        type="text"
                        className="bg-gray-800 w-full p-1 px-2 placeholder:text-slate-400"
                        placeholder="shortest estimate [eg: 5h]"
                    />
                )}
            </div>
            <div className="flex-1">
                <h4 className="font-bold">Most Likely</h4>
                <p>{actualEstimate.likely ?? "N/A"}</p>
                {!hideInputs && (
                    <input
                        value={newLikely}
                        onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewLikely(event.target.value)}
                        type="text"
                        className="bg-gray-800 w-full p-1 px-2 placeholder:text-slate-400"
                        placeholder="balanced estimate [eg: 2d 4h, or 2.5d]"
                    />
                )}
            </div>
            <div className="flex-1">
                <h4 className="font-bold">Pessimistic</h4>
                <p>{actualEstimate.pessimistic ?? "N/A"}</p>
                {!hideInputs && (
                    <input
                        value={newPessimistic}
                        onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewPessimistic(event.target.value)}
                        type="text"
                        className="bg-gray-800 w-full p-1 px-2 placeholder:text-slate-400"
                        placeholder="longest estimate [eg: 1w]"
                    />
                )}
            </div>
        </div>
        {estimateHelp && <div className="m-2 p-2 rounded-lg bg-gray-800/70 border-2 border-gray-800">
            We follow the same time scale as Gitlab, which count only worked days.<br/>
            When estimating a task to 12h, it's in fact 1 day (8h) and a half (4h).<br/>
            Time scale: 1 month = 4 weeks; 1 week = 5 days = 40 hours.<br/>
            <b>Tips:</b><br/>
            You can enter duration as days of work without units (eg: 1 or 2.5).<br/>
            You can also use following units for duration: h[ours], d[ays], w[weeks], m[onths], y[ears] (eg: 5h, 3d, 1w, 0.5m, 2y).<br/>
            Finaly, you can enter ISO 8601 duration format (eg: P1DT12H, P2W, P3M, PT5H).
        </div>}

        {!hideInputs && (
            <button
                onClick={saveEstimation}
                type="button"
                className="mt-2 bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center"
            >Save estimation</button>
        )}

        {progressBar !== undefined && <div className="p-4 pb-1 w-full">
             <progress max={1} value={progressBar} className="w-full h-2"></progress>
        </div>}
    </>);
}

export default TimeEstimateEditor

export type {PostTimeEstimate, ActualEstimate}
