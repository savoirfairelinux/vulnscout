import { useState, useEffect } from "react";
import Loading from "./pages/Loading";
import Explorer from "./pages/Explorer";


/**
 * The main application component
 * @constructor
 * @returns App A react component
 */
function App() {
  const [loading, setLoading] = useState(true);
  const [loadingText, setLoadingText] = useState({
    topline: 'Vulnerability analysis is running...',
    details: 'Starting...'
  });

  useEffect(() => {
    if (!loading) return;

    const interval = setInterval(async () => {
      fetch(import.meta.env.VITE_API_URL + "/api/scan/status", {
        mode: 'cors'
      })
      .then(res => res.json())
      .then(data => {
        if (data?.status === 'done') {
          setLoading(false);
          return;
        }
        setLoadingText({
          topline: 'Vulnerability analysis is running...',
          details: data?.message ?? 'Processing...'
        });
      })
      .catch(error => {
        console.error('Error:', error);
        setLoadingText({
          topline: 'Error fetching scan status',
          details: String(error)
        });
      });
    }, 1000);

    // Clean up the interval on unmount
    return () => clearInterval(interval);
  }, [loading]);

  return (
    <div className="dark">
      {
        loading ? (
          <Loading
            topline={loadingText.topline}
            details={loadingText.details}
          />
        ) : (
          <Explorer />
        )
      }
    </div>
  );
}

export default App
