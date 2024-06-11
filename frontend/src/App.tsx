import { useState } from "react";
import Loading from "./pages/Loading";
import Explorer from "./pages/Explorer";


/**
 * The main application component
 * @constructor
 * @returns App A react component
 */
function App() {
  const [loading, setLoading] = useState(true);
  const [darkMode, setDarkMode] = useState(true);

  setTimeout(() => {
    setLoading(false);
  }, 2000);

  return (
    <div className={darkMode ? "dark" : "light"}>
      {
        loading ? (<Loading />) : (<Explorer darkMode={darkMode} setDarkMode={setDarkMode} />)
      }
    </div>
  );
}

export default App
