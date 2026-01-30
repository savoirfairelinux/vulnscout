import infinityLoader from '/infinity_loader.svg';
import VersionDisplay from '../components/VersionDisplay';

type Props = {
  topline?: string;
  details?: string;
}

function Loading(
  {
    topline = 'Vulnerability analysis is running...',
    details = 'Step 0 : starting script'
  }: Readonly<Props>
) {
  return (
    <div className='w-screen min-h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] text-center pt-[15vh]'>
        <img src={infinityLoader} alt='Loading animation' className='min-w-[150px] m-auto' />
        <h1 id='topline' className='text-5xl p-8'>{topline}</h1>
        <h2 id='details' className='text-3xl p-8'>{details}</h2>
        <VersionDisplay />
    </div>
  )
}

export default Loading
