using Service.Models;

namespace EmailAddressVerificationAPI.Models
{
    public class ResponseDTO
    {
        public string EmailAddress { get; set; }
        //public bool Status { get; set; } = false;
        public String Status { get; set; } = "Valid";

    
        public int TotalScore { get; set; } = 0;
        public List<ChecklistElementDTO> ChecklistElements { get; set; }

        public ResponseDTO(List<ChecklistElementDTO> _checklistElements)
        {
            ChecklistElements = _checklistElements;
        }
    }
}