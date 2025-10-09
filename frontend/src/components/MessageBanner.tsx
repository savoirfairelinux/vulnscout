import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTimesCircle, faCheckCircle, faTimes } from "@fortawesome/free-solid-svg-icons";

type MessageBannerProps = {
  type: "error" | "success";
  message: string;
  isVisible: boolean;
  onClose: () => void;
};

function MessageBanner({ 
  type, 
  message, 
  isVisible, 
  onClose
}: MessageBannerProps) {

  if (!isVisible) return null;

  const bannerConfig = {
    error: {
      styles: "bg-red-600 border-red-700",
      icon: faTimesCircle
    },
    success: {
      styles: "bg-green-600 border-green-700", 
      icon: faCheckCircle
    }
  };

  const bannerClasses = bannerConfig[type].styles;
  const icon = bannerConfig[type].icon;

  return (
    <div className={`${bannerClasses} p-4 rounded-lg shadow-lg relative mb-4`}>
      <div className="flex items-center">
        <div className="flex-shrink-0">
          <FontAwesomeIcon 
            icon={icon} 
            className="h-5 w-5 text-white" 
          />
        </div>
        <div className="ml-3">
          <p className="text-sm font-medium text-white">
            {message}
          </p>
        </div>
        <div className="ml-auto pl-3">
          <div className="-mx-1.5 -my-1.5">
            <button
              onClick={onClose}
              className="inline-flex rounded-md p-1.5 text-white hover:bg-black hover:bg-opacity-20 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-white focus:ring-offset-red-600 transition-colors"
            >
              <span className="sr-only">Dismiss</span>
              <FontAwesomeIcon icon={faTimes} className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default MessageBanner;
