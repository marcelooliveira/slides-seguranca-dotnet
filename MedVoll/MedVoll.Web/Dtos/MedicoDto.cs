using MedVoll.Web.Models;

namespace MedVoll.Web.Dtos
{
    public class MedicoDto
    {
        public MedicoDto()
        {
        }

        public MedicoDto(Medico medico)
        {
            Id = medico.Id;
            Nome = medico.Nome;
            Email = medico.Email;
            Telefone = medico.Telefone;
            Crm = medico.Crm;
            Especialidade = medico.Especialidade;
        }

        public long? Id { get; set; }
        public string _method { get; set; }
        public string Nome { get; set; }
        public string Email { get; set; }
        public string Crm { get; set; }
        public string Telefone { get; set; }
        public Especialidade Especialidade { get; set; }
    }
}


