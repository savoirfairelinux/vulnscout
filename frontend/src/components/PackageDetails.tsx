import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faChevronDown, faChevronUp } from '@fortawesome/free-solid-svg-icons';
import { useState } from "react";

type PackageDetailsProps = {
    title: string,
    children: React.ReactNode | React.ReactNode[]
}

function PackageDetails ({title, children} : Readonly<PackageDetailsProps>) {
    const [show, setShow] = useState<boolean>(false);

    return <>
        <h3 className="p-2 text-slate-200" onClick={() => setShow(!show)}>{title} <FontAwesomeIcon icon={show ? faChevronUp : faChevronDown} className='ml-1' /></h3>
        <ul className={['ml-4', 'bg-slate-600', show ? 'display' : 'hidden'].join(' ')}>
            {children}
        </ul>
    </>
}

export default PackageDetails;
