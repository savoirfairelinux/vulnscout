import infinityLoader from '/infinity_loader.svg';

function Loading() {
  return (
    <div className='w-screen min-h-screen bg-gray-200 dark:bg-neutral-800 dark:text-[#eee] text-center pt-[15vh]'>
        <img src={infinityLoader} alt='Loading animation' className='min-w-[150px] m-auto' />
        <h1 id='topline' className='text-5xl p-8'>Project analysis is running...</h1>
        <h2 id='details' className='text-3xl p-8'>Step 0 : starting script</h2>
    </div>
  )
}

export default Loading
