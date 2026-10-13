import { Link } from 'react-router-dom';
import { ROUTES } from '../routes';

function NotFound() {
  return (
    <div className="text-center pt-[15vh]">
      <h1 className="text-5xl p-8">404</h1>
      <h2 className="text-xl text-gray-600 dark:text-gray-300 p-4">Page not found</h2>
      <Link
        to={ROUTES.metrics}
        className="inline-block mt-4 rounded-md bg-sky-700 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-600 focus:outline-none focus:ring-2 focus:ring-sky-400"
      >
        Back to dashboard
      </Link>
    </div>
  );
}

export default NotFound;
