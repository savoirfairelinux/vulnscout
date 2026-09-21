import HelpPopover from './HelpPopover';

type Props = {
    heading: string;
    text: string;
    ariaLabel: string;
};

export default function HintButton({ heading, text, ariaLabel }: Readonly<Props>) {
    return (
        <HelpPopover ariaLabel={ariaLabel} title={`View ${heading.toLowerCase()}`} heading={heading}>
            {text}
        </HelpPopover>
    );
}