import infinityLoader from '/infinity_loader.svg';

type Props = {
  topline?: string;
  details?: string;
  progress?: number;
}

function Loading(
  {
    topline = 'Project analysis is running...',
    details = 'Step 0 : starting script',
    progress
  }: Readonly<Props>
) {
  return (
    <div className='w-screen min-h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] text-center pt-[15vh]'>
      <img src={infinityLoader} alt='Loading animation' className='min-w-[150px] m-auto' />
      <h1 id='topline' className='text-5xl p-8'>{topline}</h1>
      <h2 id='details' className='text-3xl p-4'>{details}</h2>

      {progress !== null && (
        <>
          <div className='w-1/2 mx-auto bg-gray-300 dark:bg-neutral-700 h-4 rounded-full overflow-hidden'>
            <div
              className='bg-green-500 h-4 transition-all duration-500 ease-out'
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className='text-xl mt-2'>{progress}%</p>
        </>
      )}
    </div>
  )
}

export default Loading
