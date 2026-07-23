import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChevronDown, faChevronUp } from '@fortawesome/free-solid-svg-icons';
import { useState } from "react";

type PackageDetailsProps = {
    title: string,
    children: React.ReactNode | React.ReactNode[]
}

function PackageDetails ({title, children} : Readonly<PackageDetailsProps>) {
    const [show, setShow] = useState<boolean>(false);
    const detailsId = `package-details-${title.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;

    return <>
        <h3 className="p-2 text-slate-200">
            <button type="button" onClick={() => setShow(!show)} aria-expanded={show} aria-controls={detailsId}>
                {title} <FontAwesomeIcon icon={show ? faChevronUp : faChevronDown} className='ml-1' aria-hidden="true" />
            </button>
        </h3>
        <ul id={detailsId} className={['ml-4', 'bg-slate-600', show ? 'display' : 'hidden'].join(' ')}>
            {children}
        </ul>
    </>
}

export default PackageDetails;
